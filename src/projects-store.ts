import { randomBytes } from 'node:crypto'

import { pool } from './store.js'

export type ProjectStatus = 'ACTIVE_HEALTHY' | 'COMING_UP' | 'GOING_DOWN' | 'INIT_FAILED'

export type ProjectRecord = {
  id: number
  ref: string
  name: string
  organization_id: number
  status: ProjectStatus
  status_detail: string | null
  inserted_at: Date
  updated_at: Date
}

export type OrganizationRecord = {
  id: number
  slug: string
  name: string
  opt_in_tags: string[]
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
    alter table management.organizations
      add column if not exists opt_in_tags jsonb not null default '[]'::jsonb;
    alter table management.projects
      add column if not exists db_port int;
    alter table management.organizations
      add column if not exists mfa_enforced boolean not null default false;
  `)
}

const PROJECT_COLUMNS =
  'id, ref, name, organization_id, status, status_detail, inserted_at, updated_at'

export async function listProjects(): Promise<ProjectRecord[]> {
  const { rows } = await pool.query(
    `select ${PROJECT_COLUMNS} from management.projects where kind = 'default' order by id`
  )
  return rows
}

export async function getProject(ref: string): Promise<ProjectRecord | null> {
  const { rows } = await pool.query(
    `select ${PROJECT_COLUMNS} from management.projects where ref = $1 and kind = 'default'`,
    [ref]
  )
  return rows[0] ?? null
}

export async function listOrganizations(): Promise<OrganizationRecord[]> {
  const { rows } = await pool.query(
    'select id, slug, name, opt_in_tags from management.organizations order by id'
  )
  return rows
}

export async function getOrganization(slug: string): Promise<OrganizationRecord | null> {
  const { rows } = await pool.query(
    'select id, slug, name, opt_in_tags from management.organizations where slug = $1',
    [slug]
  )
  return rows[0] ?? null
}

export async function updateOrganization(
  slug: string,
  patch: { name?: string; opt_in_tags?: string[] }
): Promise<OrganizationRecord | null> {
  const { rows } = await pool.query(
    `update management.organizations
       set name = coalesce($2, name),
           opt_in_tags = coalesce($3::jsonb, opt_in_tags)
     where slug = $1
     returning id, slug, name, opt_in_tags`,
    [slug, patch.name ?? null, patch.opt_in_tags ? JSON.stringify(patch.opt_in_tags) : null]
  )
  return rows[0] ?? null
}

export async function getOrganizationMfaEnforced(slug: string): Promise<boolean | null> {
  const { rows } = await pool.query(
    'select mfa_enforced from management.organizations where slug = $1',
    [slug]
  )
  return rows[0]?.mfa_enforced ?? null
}

export async function setOrganizationMfaEnforced(
  slug: string,
  enforced: boolean
): Promise<boolean | null> {
  const { rows } = await pool.query(
    'update management.organizations set mfa_enforced = $2 where slug = $1 returning mfa_enforced',
    [slug, enforced]
  )
  return rows[0]?.mfa_enforced ?? null
}

/** True when any organization requires members to have MFA enabled. */
export async function isMfaEnforcedAnywhere(): Promise<boolean> {
  const { rows } = await pool.query(
    'select 1 from management.organizations where mfa_enforced limit 1'
  )
  return rows.length > 0
}

export async function createOrganization(name: string): Promise<OrganizationRecord> {
  const slug = `${name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 30) || 'org'}-${randomBytes(3).toString('hex')}`
  const { rows } = await pool.query(
    'insert into management.organizations (slug, name) values ($1, $2) returning id, slug, name, opt_in_tags',
    [slug, name]
  )
  return rows[0]
}
