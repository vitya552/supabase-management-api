import { createHash, randomBytes, scrypt, timingSafeEqual } from 'node:crypto'
import { promisify } from 'node:util'

import { pool } from './store.js'

const scryptAsync = promisify(scrypt)

export type DashboardRole = 'owner' | 'admin' | 'developer'

export type DashboardUser = {
  id: number
  username: string
  role: DashboardRole
  inserted_at: Date
}

export const DASHBOARD_ROLES: ReadonlySet<string> = new Set([
  'owner',
  'admin',
  'developer',
])

export async function migrateDashboardUsers(): Promise<void> {
  await pool.query(`
    create table if not exists management.dashboard_users (
      id serial primary key,
      username text not null unique,
      password_hash text not null,
      role text not null check (role in ('owner', 'admin', 'developer')),
      inserted_at timestamptz not null default now()
    );
    create table if not exists management.dashboard_invitations (
      id serial primary key,
      token_hash text not null unique,
      role text not null check (role in ('owner', 'admin', 'developer')),
      invited_by text not null,
      expires_at timestamptz not null,
      consumed_at timestamptz,
      inserted_at timestamptz not null default now()
    );
  `)
}

async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString('hex')
  const derived = (await scryptAsync(password, salt, 64)) as Buffer
  return `${salt}:${derived.toString('hex')}`
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [salt, expectedHex] = stored.split(':')
  if (!salt || !expectedHex) return false
  const derived = (await scryptAsync(password, salt, 64)) as Buffer
  const expected = Buffer.from(expectedHex, 'hex')
  return derived.length === expected.length && timingSafeEqual(derived, expected)
}

export async function listDashboardUsers(): Promise<DashboardUser[]> {
  const { rows } = await pool.query(
    'select id, username, role, inserted_at from management.dashboard_users order by id'
  )
  return rows
}

export async function createDashboardUser(input: {
  username: string
  password: string
  role: DashboardRole
}): Promise<DashboardUser> {
  const passwordHash = await hashPassword(input.password)
  const { rows } = await pool.query(
    `insert into management.dashboard_users (username, password_hash, role)
     values ($1, $2, $3)
     returning id, username, role, inserted_at`,
    [input.username, passwordHash, input.role]
  )
  return rows[0]
}

export async function deleteDashboardUser(
  username: string
): Promise<{ deleted: boolean; lastOwner: boolean }> {
  // The last remaining owner cannot be removed, so the dashboard always has
  // at least one account able to manage users. (The env break-glass login is
  // an owner too, but it may be disabled.)
  const { rows } = await pool.query(
    `select role,
            (select count(*) from management.dashboard_users where role = 'owner') as owner_count
     from management.dashboard_users where username = $1`,
    [username]
  )
  const target = rows[0]
  if (target && target.role === 'owner' && Number(target.owner_count) <= 1) {
    return { deleted: false, lastOwner: true }
  }
  const { rowCount } = await pool.query(
    'delete from management.dashboard_users where username = $1',
    [username]
  )
  return { deleted: (rowCount ?? 0) > 0, lastOwner: false }
}

export type DashboardInvitation = {
  id: number
  role: DashboardRole
  invited_by: string
  expires_at: Date
  consumed_at: Date | null
  inserted_at: Date
}

const INVITATION_TTL_MS = 7 * 24 * 60 * 60 * 1000

function hashInvitationToken(token: string): string {
  return createHash('sha256').update(token).digest('hex')
}

/** Creates an invitation; only the sha256 hash of the token is stored. */
export async function createInvitation(input: {
  role: DashboardRole
  invitedBy: string
}): Promise<{ invitation: DashboardInvitation; token: string }> {
  const token = randomBytes(32).toString('base64url')
  const { rows } = await pool.query(
    `insert into management.dashboard_invitations (token_hash, role, invited_by, expires_at)
     values ($1, $2, $3, $4)
     returning id, role, invited_by, expires_at, consumed_at, inserted_at`,
    [hashInvitationToken(token), input.role, input.invitedBy, new Date(Date.now() + INVITATION_TTL_MS)]
  )
  return { invitation: rows[0], token }
}

export async function listInvitations(): Promise<DashboardInvitation[]> {
  const { rows } = await pool.query(
    `select id, role, invited_by, expires_at, consumed_at, inserted_at
     from management.dashboard_invitations order by id desc`
  )
  return rows
}

export async function deleteInvitation(id: number): Promise<boolean> {
  const { rowCount } = await pool.query(
    'delete from management.dashboard_invitations where id = $1',
    [id]
  )
  return (rowCount ?? 0) > 0
}

/**
 * Consumes an invitation token and creates the invited user atomically.
 * Tokens are single-use and expire; the invited role is fixed at invite time.
 */
export async function acceptInvitation(input: {
  token: string
  username: string
  password: string
}): Promise<DashboardUser | 'invalid_token' | 'username_taken'> {
  const client = await pool.connect()
  try {
    await client.query('begin')
    const { rows } = await client.query(
      `update management.dashboard_invitations
       set consumed_at = now()
       where token_hash = $1 and consumed_at is null and expires_at > now()
       returning role`,
      [hashInvitationToken(input.token)]
    )
    const invitation = rows[0]
    if (!invitation) {
      await client.query('rollback')
      return 'invalid_token'
    }
    const passwordHash = await hashPassword(input.password)
    try {
      const inserted = await client.query(
        `insert into management.dashboard_users (username, password_hash, role)
         values ($1, $2, $3)
         returning id, username, role, inserted_at`,
        [input.username, passwordHash, invitation.role]
      )
      await client.query('commit')
      return inserted.rows[0]
    } catch {
      await client.query('rollback')
      return 'username_taken'
    }
  } finally {
    client.release()
  }
}

/** Checks a login against the dashboard users stored in the database. */
export async function verifyDashboardUser(
  username: string,
  password: string
): Promise<DashboardUser | null> {
  const { rows } = await pool.query(
    'select id, username, password_hash, role, inserted_at from management.dashboard_users where username = $1',
    [username]
  )
  const row = rows[0]
  if (!row) return null
  const isValid = await verifyPassword(password, row.password_hash)
  if (!isValid) return null
  return { id: row.id, username: row.username, role: row.role, inserted_at: row.inserted_at }
}
