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
  `)
  await encryptLegacyPlaintextRows()
}

/** One-time upgrade: encrypt rows written before encryption at rest existed. */
async function encryptLegacyPlaintextRows(): Promise<void> {
  const { rows: secretRows } = await pool.query(
    'select name, value from management.function_secrets'
  )
  for (const row of secretRows) {
    if (!isEncrypted(row.value)) {
      await pool.query(
        'update management.function_secrets set value = $2 where name = $1',
        [row.name, encryptString(row.value)]
      )
    }
  }

  const { rows: configRows } = await pool.query('select key, value from management.auth_config')
  for (const row of configRows) {
    if (!isSensitiveConfigKey(row.key)) continue
    const value = row.value
    if (typeof value === 'string' && isEncrypted(value)) continue
    await pool.query('update management.auth_config set value = $2::jsonb where key = $1', [
      row.key,
      JSON.stringify(encryptString(JSON.stringify(value))),
    ])
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

export async function getEdgeFunctions(): Promise<EdgeFunctionRecord[]> {
  const { rows } = await pool.query('select * from management.edge_functions order by slug')
  return rows
}

export async function getEdgeFunction(slug: string): Promise<EdgeFunctionRecord | null> {
  const { rows } = await pool.query('select * from management.edge_functions where slug = $1', [
    slug,
  ])
  return rows[0] ?? null
}

export async function upsertEdgeFunction(fn: {
  slug: string
  name: string
  verify_jwt: boolean
  entrypoint_path: string | null
  import_map_path: string | null
}): Promise<EdgeFunctionRecord> {
  const { rows } = await pool.query(
    `insert into management.edge_functions (slug, name, verify_jwt, entrypoint_path, import_map_path)
     values ($1, $2, $3, $4, $5)
     on conflict (slug) do update
       set name = excluded.name,
           verify_jwt = excluded.verify_jwt,
           entrypoint_path = excluded.entrypoint_path,
           import_map_path = excluded.import_map_path,
           version = management.edge_functions.version + 1,
           updated_at = now()
     returning *`,
    [fn.slug, fn.name, fn.verify_jwt, fn.entrypoint_path, fn.import_map_path]
  )
  return rows[0]
}

export async function updateEdgeFunction(
  slug: string,
  patch: { name?: string; verify_jwt?: boolean }
): Promise<EdgeFunctionRecord | null> {
  const { rows } = await pool.query(
    `update management.edge_functions
       set name = coalesce($2, name),
           verify_jwt = coalesce($3, verify_jwt),
           updated_at = now()
     where slug = $1
     returning *`,
    [slug, patch.name ?? null, patch.verify_jwt ?? null]
  )
  return rows[0] ?? null
}

export async function deleteEdgeFunction(slug: string): Promise<void> {
  await pool.query('delete from management.edge_functions where slug = $1', [slug])
}

export type FunctionSecret = { name: string; value: string; updated_at: Date }

export async function getFunctionSecrets(): Promise<FunctionSecret[]> {
  const { rows } = await pool.query('select * from management.function_secrets order by name')
  return rows.map((row) => ({ ...row, value: decryptString(row.value) }))
}

export async function upsertFunctionSecrets(
  secrets: Array<{ name: string; value: string }>
): Promise<void> {
  if (secrets.length === 0) return
  const client = await pool.connect()
  try {
    await client.query('begin')
    for (const secret of secrets) {
      await client.query(
        `insert into management.function_secrets (name, value) values ($1, $2)
         on conflict (name) do update set value = excluded.value, updated_at = now()`,
        [secret.name, encryptString(secret.value)]
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

export async function deleteFunctionSecrets(names: string[]): Promise<void> {
  if (names.length === 0) return
  await pool.query('delete from management.function_secrets where name = any($1)', [names])
}

export async function getAllConfig(): Promise<Record<string, ConfigValue>> {
  const { rows } = await pool.query('select key, value from management.auth_config')
  const out: Record<string, ConfigValue> = {}
  for (const row of rows) {
    const value = row.value
    if (typeof value === 'string' && isEncrypted(value)) {
      out[row.key] = JSON.parse(decryptString(value))
    } else {
      out[row.key] = value
    }
  }
  return out
}

export async function upsertConfig(entries: Record<string, ConfigValue>): Promise<void> {
  const keys = Object.keys(entries)
  if (keys.length === 0) return
  const client = await pool.connect()
  try {
    await client.query('begin')
    for (const key of keys) {
      const value = entries[key]
      if (value === null) {
        await client.query('delete from management.auth_config where key = $1', [key])
      } else {
        const serialized = isSensitiveConfigKey(key)
          ? JSON.stringify(encryptString(JSON.stringify(value)))
          : JSON.stringify(value)
        await client.query(
          `insert into management.auth_config (key, value) values ($1, $2::jsonb)
           on conflict (key) do update set value = excluded.value, updated_at = now()`,
          [key, serialized]
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

export async function deleteConfig(keys: string[]): Promise<void> {
  if (keys.length === 0) return
  await pool.query('delete from management.auth_config where key = any($1)', [keys])
}

export type EmailTemplate = {
  template_type: string
  source: string
  source_format: 'html' | 'react'
  rendered_html: string
}

export async function getEmailTemplate(templateType: string): Promise<EmailTemplate | null> {
  const { rows } = await pool.query(
    'select template_type, source, source_format, rendered_html from management.email_templates where template_type = $1',
    [templateType]
  )
  return rows[0] ?? null
}

export async function getAllEmailTemplates(): Promise<EmailTemplate[]> {
  const { rows } = await pool.query(
    'select template_type, source, source_format, rendered_html from management.email_templates'
  )
  return rows
}

export async function upsertEmailTemplate(template: EmailTemplate): Promise<void> {
  await pool.query(
    `insert into management.email_templates (template_type, source, source_format, rendered_html)
     values ($1, $2, $3, $4)
     on conflict (template_type) do update
       set source = excluded.source,
           source_format = excluded.source_format,
           rendered_html = excluded.rendered_html,
           updated_at = now()`,
    [template.template_type, template.source, template.source_format, template.rendered_html]
  )
}

export async function deleteEmailTemplate(templateType: string): Promise<void> {
  await pool.query('delete from management.email_templates where template_type = $1', [
    templateType,
  ])
}
