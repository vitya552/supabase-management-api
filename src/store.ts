import pg from 'pg'

import { decryptString, encryptString, isEncrypted, isSensitiveConfigKey } from './crypto.js'
import { env } from './env.js'

export const pool = new pg.Pool({ connectionString: env.databaseUrl })

export type ConfigValue = string | number | boolean | null

export async function migrate(): Promise<void> {
  await pool.query(`
    create schema if not exists management;
    create table if not exists management.auth_config (
      key text primary key,
      value jsonb not null,
      updated_at timestamptz not null default now()
    );
    create table if not exists management.email_templates (
      template_type text primary key,
      source text not null,
      source_format text not null default 'html',
      rendered_html text not null,
      updated_at timestamptz not null default now()
    );
    create table if not exists management.edge_functions (
      slug text primary key,
      name text not null,
      version int not null default 1,
      verify_jwt boolean not null default true,
      entrypoint_path text,
      import_map_path text,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now()
    );
    create table if not exists management.function_secrets (
      name text primary key,
      value text not null,
      updated_at timestamptz not null default now()
    );
    alter table management.edge_functions
      add column if not exists project_ref text not null default 'default';
    alter table management.function_secrets
      add column if not exists project_ref text not null default 'default';
    alter table management.auth_config
      add column if not exists project_ref text not null default 'default';
    alter table management.email_templates
      add column if not exists project_ref text not null default 'default';
    do $$ begin
      if not exists (
        select 1 from pg_constraint where conname = 'edge_functions_project_ref_slug_key'
      ) then
        alter table management.edge_functions drop constraint edge_functions_pkey;
        alter table management.edge_functions
          add constraint edge_functions_project_ref_slug_key primary key (project_ref, slug);
      end if;
      if not exists (
        select 1 from pg_constraint where conname = 'function_secrets_project_ref_name_key'
      ) then
        alter table management.function_secrets drop constraint function_secrets_pkey;
        alter table management.function_secrets
          add constraint function_secrets_project_ref_name_key primary key (project_ref, name);
      end if;
      if not exists (
        select 1 from pg_constraint where conname = 'auth_config_project_ref_key_key'
      ) then
        alter table management.auth_config drop constraint auth_config_pkey;
        alter table management.auth_config
          add constraint auth_config_project_ref_key_key primary key (project_ref, key);
      end if;
      if not exists (
        select 1 from pg_constraint where conname = 'email_templates_project_ref_type_key'
      ) then
        alter table management.email_templates drop constraint email_templates_pkey;
        alter table management.email_templates
          add constraint email_templates_project_ref_type_key primary key (project_ref, template_type);
      end if;
    end $$;
  `)
  await encryptLegacyPlaintextRows()
}

/** One-time upgrade: encrypt rows written before encryption at rest existed. */
async function encryptLegacyPlaintextRows(): Promise<void> {
  const { rows: secretRows } = await pool.query(
    'select project_ref, name, value from management.function_secrets'
  )
  for (const row of secretRows) {
    if (!isEncrypted(row.value)) {
      await pool.query(
        'update management.function_secrets set value = $3 where project_ref = $1 and name = $2',
        [row.project_ref, row.name, encryptString(row.value, row.name)]
      )
    }
  }

  const { rows: configRows } = await pool.query(
    'select project_ref, key, value from management.auth_config'
  )
  for (const row of configRows) {
    if (!isSensitiveConfigKey(row.key)) continue
    const value = row.value
    if (typeof value === 'string' && isEncrypted(value)) continue
    await pool.query(
      'update management.auth_config set value = $3::jsonb where project_ref = $1 and key = $2',
      [row.project_ref, row.key, JSON.stringify(encryptString(JSON.stringify(value), row.key))]
    )
  }
}

export type EdgeFunctionRecord = {
  slug: string
  name: string
  version: number
  verify_jwt: boolean
  entrypoint_path: string | null
  import_map_path: string | null
  created_at: Date
  updated_at: Date
}

export async function getEdgeFunctions(projectRef: string): Promise<EdgeFunctionRecord[]> {
  const { rows } = await pool.query(
    'select * from management.edge_functions where project_ref = $1 order by slug',
    [projectRef]
  )
  return rows
}

export async function getEdgeFunction(
  projectRef: string,
  slug: string
): Promise<EdgeFunctionRecord | null> {
  const { rows } = await pool.query(
    'select * from management.edge_functions where project_ref = $1 and slug = $2',
    [projectRef, slug]
  )
  return rows[0] ?? null
}

export async function upsertEdgeFunction(
  projectRef: string,
  fn: {
    slug: string
    name: string
    verify_jwt: boolean
    entrypoint_path: string | null
    import_map_path: string | null
  }
): Promise<EdgeFunctionRecord> {
  const { rows } = await pool.query(
    `insert into management.edge_functions (project_ref, slug, name, verify_jwt, entrypoint_path, import_map_path)
     values ($1, $2, $3, $4, $5, $6)
     on conflict (project_ref, slug) do update
       set name = excluded.name,
           verify_jwt = excluded.verify_jwt,
           entrypoint_path = excluded.entrypoint_path,
           import_map_path = excluded.import_map_path,
           version = management.edge_functions.version + 1,
           updated_at = now()
     returning *`,
    [projectRef, fn.slug, fn.name, fn.verify_jwt, fn.entrypoint_path, fn.import_map_path]
  )
  return rows[0]
}

export async function updateEdgeFunction(
  projectRef: string,
  slug: string,
  patch: { name?: string; verify_jwt?: boolean }
): Promise<EdgeFunctionRecord | null> {
  const { rows } = await pool.query(
    `update management.edge_functions
       set name = coalesce($3, name),
           verify_jwt = coalesce($4, verify_jwt),
           updated_at = now()
     where project_ref = $1 and slug = $2
     returning *`,
    [projectRef, slug, patch.name ?? null, patch.verify_jwt ?? null]
  )
  return rows[0] ?? null
}

export async function deleteEdgeFunction(projectRef: string, slug: string): Promise<void> {
  await pool.query(
    'delete from management.edge_functions where project_ref = $1 and slug = $2',
    [projectRef, slug]
  )
}

/** Removes all function rows belonging to a project (used on deprovision). */
export async function deleteProjectFunctionData(projectRef: string): Promise<void> {
  await pool.query('delete from management.edge_functions where project_ref = $1', [projectRef])
  await pool.query('delete from management.function_secrets where project_ref = $1', [projectRef])
}

export type FunctionSecret = { name: string; value: string; updated_at: Date }

export async function getFunctionSecrets(projectRef: string): Promise<FunctionSecret[]> {
  const { rows } = await pool.query(
    'select * from management.function_secrets where project_ref = $1 order by name',
    [projectRef]
  )
  return rows.map((row) => ({
    ...row,
    value: isEncrypted(row.value) ? decryptString(row.value, row.name) : row.value,
  }))
}

export async function upsertFunctionSecrets(
  projectRef: string,
  secrets: Array<{ name: string; value: string }>
): Promise<void> {
  if (secrets.length === 0) return
  const client = await pool.connect()
  try {
    await client.query('begin')
    for (const secret of secrets) {
      await client.query(
        `insert into management.function_secrets (project_ref, name, value) values ($1, $2, $3)
         on conflict (project_ref, name) do update set value = excluded.value, updated_at = now()`,
        [projectRef, secret.name, encryptString(secret.value, secret.name)]
      )
    }
    await client.query('commit')
  } catch (err) {
    await client.query('rollback')
    throw err
  } finally {
    client.release()
  }
}

export async function deleteFunctionSecrets(projectRef: string, names: string[]): Promise<void> {
  if (names.length === 0) return
  await pool.query(
    'delete from management.function_secrets where project_ref = $1 and name = any($2)',
    [projectRef, names]
  )
}

export async function getAllConfig(projectRef: string): Promise<Record<string, ConfigValue>> {
  const { rows } = await pool.query(
    'select key, value from management.auth_config where project_ref = $1',
    [projectRef]
  )
  const out: Record<string, ConfigValue> = {}
  for (const row of rows) {
    const value = row.value
    // Only values stored under sensitive keys are encrypted, so a plain string
    // that merely looks like a ciphertext under any other key is passed through
    // untouched instead of failing the whole read.
    if (isSensitiveConfigKey(row.key) && typeof value === 'string' && isEncrypted(value)) {
      out[row.key] = JSON.parse(decryptString(value, row.key))
    } else {
      out[row.key] = value
    }
  }
  return out
}

export async function upsertConfig(
  projectRef: string,
  entries: Record<string, ConfigValue>
): Promise<void> {
  const keys = Object.keys(entries)
  if (keys.length === 0) return
  const client = await pool.connect()
  try {
    await client.query('begin')
    for (const key of keys) {
      const value = entries[key]
      if (value === null) {
        await client.query(
          'delete from management.auth_config where project_ref = $1 and key = $2',
          [projectRef, key]
        )
      } else {
        const serialized = isSensitiveConfigKey(key)
          ? JSON.stringify(encryptString(JSON.stringify(value), key))
          : JSON.stringify(value)
        await client.query(
          `insert into management.auth_config (project_ref, key, value) values ($1, $2, $3::jsonb)
           on conflict (project_ref, key) do update set value = excluded.value, updated_at = now()`,
          [projectRef, key, serialized]
        )
      }
    }
    await client.query('commit')
  } catch (err) {
    await client.query('rollback')
    throw err
  } finally {
    client.release()
  }
}

export async function deleteConfig(projectRef: string, keys: string[]): Promise<void> {
  if (keys.length === 0) return
  await pool.query(
    'delete from management.auth_config where project_ref = $1 and key = any($2)',
    [projectRef, keys]
  )
}

/** Removes all auth config and templates belonging to a project (deprovision). */
export async function deleteProjectAuthData(projectRef: string): Promise<void> {
  await pool.query('delete from management.auth_config where project_ref = $1', [projectRef])
  await pool.query('delete from management.email_templates where project_ref = $1', [projectRef])
}

export type EmailTemplate = {
  template_type: string
  source: string
  source_format: 'html' | 'react'
  rendered_html: string
}

export async function getEmailTemplate(
  projectRef: string,
  templateType: string
): Promise<EmailTemplate | null> {
  const { rows } = await pool.query(
    'select template_type, source, source_format, rendered_html from management.email_templates where project_ref = $1 and template_type = $2',
    [projectRef, templateType]
  )
  return rows[0] ?? null
}

export async function getAllEmailTemplates(projectRef: string): Promise<EmailTemplate[]> {
  const { rows } = await pool.query(
    'select template_type, source, source_format, rendered_html from management.email_templates where project_ref = $1',
    [projectRef]
  )
  return rows
}

export async function upsertEmailTemplate(
  projectRef: string,
  template: EmailTemplate
): Promise<void> {
  await pool.query(
    `insert into management.email_templates (project_ref, template_type, source, source_format, rendered_html)
     values ($1, $2, $3, $4, $5)
     on conflict (project_ref, template_type) do update
       set source = excluded.source,
           source_format = excluded.source_format,
           rendered_html = excluded.rendered_html,
           updated_at = now()`,
    [
      projectRef,
      template.template_type,
      template.source,
      template.source_format,
      template.rendered_html,
    ]
  )
}

export async function deleteEmailTemplate(
  projectRef: string,
  templateType: string
): Promise<void> {
  await pool.query(
    'delete from management.email_templates where project_ref = $1 and template_type = $2',
    [projectRef, templateType]
  )
}
