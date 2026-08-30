import { randomBytes } from 'node:crypto'

import { decryptString, encryptString, isEncrypted } from './crypto.js'
import { pool } from './store.js'

export type ProjectKind = 'default' | 'compose' | 'external'

export type ProjectStatus =
  | 'ACTIVE_HEALTHY'
  | 'COMING_UP'
  | 'GOING_DOWN'
  | 'INIT_FAILED'
  | 'REMOVED'

export type ProjectSecrets = {
  postgres_password: string
  jwt_secret: string
  anon_key: string
  service_role_key: string
}

export type ProjectRecord = {
  id: number
  ref: string
  name: string
  organization_id: number
  kind: ProjectKind
  status: ProjectStatus
  /** External projects only: full Postgres connection string. */
  external_db_url: string | null
  secrets: ProjectSecrets | null
  status_detail: string | null
  inserted_at: Date
  updated_at: Date
}

export type OrganizationRecord = {
  id: number
  slug: string
  name: string
}

export async function migrateProjects(): Promise<void> {
  await pool.query(`
    create table if not exists management.organizations (
      id serial primary key,
      slug text not null unique,
      name text not null,
      inserted_at timestamptz not null default now()
    );
    create table if not exists management.projects (
      id serial primary key,
      ref text not null unique,
      name text not null,
      organization_id int not null references management.organizations(id),
      kind text not null check (kind in ('default', 'compose', 'external')),
      status text not null default 'COMING_UP',
      external_db_url text,
      secrets jsonb,
      status_detail text,
      inserted_at timestamptz not null default now(),
      updated_at timestamptz not null default now()
    );
    insert into management.organizations (id, slug, name)
      values (1, 'default-org-slug', 'Default Organization')
      on conflict (id) do nothing;
    select setval('management.organizations_id_seq',
      (select greatest(max(id), 1) from management.organizations));
    insert into management.projects (id, ref, name, organization_id, kind, status)
      values (1, 'default', 'Default Project', 1, 'default', 'ACTIVE_HEALTHY')
      on conflict (id) do nothing;
    select setval('management.projects_id_seq',
      (select greatest(max(id), 1) from management.projects));
  `)
}

const SECRET_CONTEXT = 'project-secrets'
const EXTERNAL_DB_CONTEXT = 'project-external-db'

function rowToProject(row: {
  id: number
  ref: string
  name: string
  organization_id: number
  kind: ProjectKind
  status: ProjectStatus
  external_db_url: string | null
  secrets: string | null
  status_detail: string | null
  inserted_at: Date
  updated_at: Date
}): ProjectRecord {
  return {
    ...row,
    external_db_url:
      row.external_db_url !== null && isEncrypted(row.external_db_url)
        ? decryptString(row.external_db_url, EXTERNAL_DB_CONTEXT)
        : row.external_db_url,
    secrets:
      typeof row.secrets === 'string' && isEncrypted(row.secrets)
        ? (JSON.parse(decryptString(row.secrets, SECRET_CONTEXT)) as ProjectSecrets)
        : null,
  }
}

export async function listProjects(): Promise<ProjectRecord[]> {
  const { rows } = await pool.query(
    `select * from management.projects where status <> 'REMOVED' order by id`
  )
  return rows.map(rowToProject)
}

export async function getProject(ref: string): Promise<ProjectRecord | null> {
  const { rows } = await pool.query(
    `select * from management.projects where ref = $1 and status <> 'REMOVED'`,
    [ref]
  )
  return rows[0] ? rowToProject(rows[0]) : null
}

export async function createProjectRecord(input: {
  ref: string
  name: string
  organizationId: number
  kind: 'compose' | 'external'
  externalDbUrl?: string
  secrets?: ProjectSecrets
  status: ProjectStatus
}): Promise<ProjectRecord> {
  const { rows } = await pool.query(
    `insert into management.projects
       (ref, name, organization_id, kind, status, external_db_url, secrets)
     values ($1, $2, $3, $4, $5, $6, $7::jsonb)
     returning *`,
    [
      input.ref,
      input.name,
      input.organizationId,
      input.kind,
      input.status,
      input.externalDbUrl ? encryptString(input.externalDbUrl, EXTERNAL_DB_CONTEXT) : null,
      input.secrets
        ? JSON.stringify(encryptString(JSON.stringify(input.secrets), SECRET_CONTEXT))
        : null,
    ]
  )
  return rowToProject(rows[0])
}

export async function updateProjectStatus(
  ref: string,
  status: ProjectStatus,
  detail: string | null = null
): Promise<void> {
  await pool.query(
    `update management.projects
       set status = $2, status_detail = $3, updated_at = now()
     where ref = $1`,
    [ref, status, detail]
  )
}

export async function deleteProjectRecord(ref: string): Promise<void> {
  await pool.query(`delete from management.projects where ref = $1`, [ref])
}

export async function listOrganizations(): Promise<OrganizationRecord[]> {
  const { rows } = await pool.query(
    'select id, slug, name from management.organizations order by id'
  )
  return rows
}

export async function createOrganization(name: string): Promise<OrganizationRecord> {
  const slug = `${name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 30) || 'org'}-${randomBytes(3).toString('hex')}`
  const { rows } = await pool.query(
    'insert into management.organizations (slug, name) values ($1, $2) returning id, slug, name',
    [slug, name]
  )
  return rows[0]
}

const REF_ALPHABET = 'abcdefghijklmnopqrstuvwxyz'
const REF_ALPHANUM = 'abcdefghijklmnopqrstuvwxyz0123456789'

/** 20-char lowercase ref, same shape as hosted project refs. */
export function generateRef(): string {
  const bytes = randomBytes(20)
  let out = REF_ALPHABET[bytes[0] % REF_ALPHABET.length]
  for (let i = 1; i < 20; i++) out += REF_ALPHANUM[bytes[i] % REF_ALPHANUM.length]
  return out
}
