import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto'
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

export async function deleteDashboardUser(username: string): Promise<boolean> {
  const { rowCount } = await pool.query(
    'delete from management.dashboard_users where username = $1',
    [username]
  )
  return (rowCount ?? 0) > 0
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
