import { env } from './env.js'
import { pool } from './store.js'

export type PostgrestConfig = {
  db_schema: string
  max_rows: number
  db_extra_search_path: string
  db_pool: number | null
}

const MANAGED_SETTINGS: Record<string, keyof PostgrestConfig> = {
  'pgrst.db_schemas': 'db_schema',
  'pgrst.db_max_rows': 'max_rows',
  'pgrst.db_extra_search_path': 'db_extra_search_path',
  'pgrst.db_pool': 'db_pool',
}

/**
 * Reads the effective PostgREST configuration: in-database settings on the
 * `authenticator` role (which PostgREST re-reads on `NOTIFY pgrst`) override
 * the container's environment defaults.
 */
export async function getPostgrestConfig(): Promise<PostgrestConfig> {
  const config: PostgrestConfig = {
    db_schema: env.pgrstDbSchemas,
    max_rows: env.pgrstDbMaxRows,
    db_extra_search_path: env.pgrstDbExtraSearchPath,
    db_pool: null,
  }

  const { rows } = await pool.query(
    `select coalesce(rolconfig, '{}') as rolconfig from pg_roles where rolname = 'authenticator'`
  )
  const rolconfig: string[] = rows[0]?.rolconfig ?? []
  for (const entry of rolconfig) {
    const eq = entry.indexOf('=')
    if (eq === -1) continue
    const key = entry.slice(0, eq)
    const value = entry.slice(eq + 1)
    const field = MANAGED_SETTINGS[key]
    if (!field) continue
    if (field === 'max_rows') config.max_rows = Number(value) || config.max_rows
    else if (field === 'db_pool') config.db_pool = Number(value) || null
    else config[field] = value
  }

  return config
}

function quoteLiteral(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}

/**
 * Applies PostgREST settings as in-database config on the `authenticator`
 * role and asks PostgREST to reload, so changes take effect without editing
 * env vars or restarting the container.
 */
export async function updatePostgrestConfig(patch: {
  db_schema?: string
  max_rows?: number
  db_extra_search_path?: string
  db_pool?: number | null
}): Promise<PostgrestConfig> {
  const client = await pool.connect()
  try {
    await client.query('begin')
    if (patch.db_schema !== undefined) {
      await client.query(
        `alter role authenticator set pgrst.db_schemas = ${quoteLiteral(patch.db_schema)}`
      )
    }
    if (patch.max_rows !== undefined) {
      await client.query(
        `alter role authenticator set pgrst.db_max_rows = ${quoteLiteral(String(patch.max_rows))}`
      )
    }
    if (patch.db_extra_search_path !== undefined) {
      await client.query(
        `alter role authenticator set pgrst.db_extra_search_path = ${quoteLiteral(patch.db_extra_search_path)}`
      )
    }
    if (patch.db_pool !== undefined) {
      if (patch.db_pool === null) {
        await client.query(`alter role authenticator reset pgrst.db_pool`)
      } else {
        await client.query(
          `alter role authenticator set pgrst.db_pool = ${quoteLiteral(String(patch.db_pool))}`
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

  await pool.query(`notify pgrst, 'reload config'`)
  return getPostgrestConfig()
}
