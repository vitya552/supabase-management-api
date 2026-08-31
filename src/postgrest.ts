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

function envDefaults(): Omit<PostgrestConfig, 'db_pool'> {
  return {
    db_schema: env.pgrstDbSchemas,
    max_rows: env.pgrstDbMaxRows,
    db_extra_search_path: env.pgrstDbExtraSearchPath,
  }
}

type QueryRunner = (sql: string) => Promise<{ rows: Record<string, unknown>[] }>

/**
 * Runs queries against the stack's database, where PostgREST reads role
 * config and reload notifications. Returns null for unknown refs.
 */
async function withProjectDb<T>(
  ref: string,
  fn: (query: QueryRunner) => Promise<T>
): Promise<T | null> {
  if (ref !== 'default') return null
  return fn((sql) => pool.query(sql))
}

/**
 * Reads the effective PostgREST configuration: in-database settings on the
 * `authenticator` role (which PostgREST re-reads on `NOTIFY pgrst`) override
 * the container's environment defaults.
 */
export async function getPostgrestConfig(ref: string): Promise<PostgrestConfig | null> {
  const config: PostgrestConfig = { ...envDefaults(), db_pool: null }

  const result = await withProjectDb(ref, (query) =>
    query(
      `select coalesce(rolconfig, '{}') as rolconfig from pg_roles where rolname = 'authenticator'`
    )
  )
  if (result === null) return null
  const { rows } = result as { rows: { rolconfig: string[] }[] }
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
export async function updatePostgrestConfig(
  ref: string,
  patch: {
    db_schema?: string
    max_rows?: number
    db_extra_search_path?: string
    db_pool?: number | null
  }
): Promise<PostgrestConfig | null> {
  const applied = await withProjectDb(ref, async (query) => {
    await query('begin')
    try {
      if (patch.db_schema !== undefined) {
        await query(
          `alter role authenticator set pgrst.db_schemas = ${quoteLiteral(patch.db_schema)}`
        )
      }
      if (patch.max_rows !== undefined) {
        await query(
          `alter role authenticator set pgrst.db_max_rows = ${quoteLiteral(String(patch.max_rows))}`
        )
      }
      if (patch.db_extra_search_path !== undefined) {
        await query(
          `alter role authenticator set pgrst.db_extra_search_path = ${quoteLiteral(patch.db_extra_search_path)}`
        )
      }
      if (patch.db_pool !== undefined) {
        if (patch.db_pool === null) {
          await query(`alter role authenticator reset pgrst.db_pool`)
        } else {
          await query(
            `alter role authenticator set pgrst.db_pool = ${quoteLiteral(String(patch.db_pool))}`
          )
        }
      }
      await query('commit')
    } catch (err) {
      await query('rollback')
      throw err
    }
    await query(`notify pgrst, 'reload config'`)
    return true
  })
  if (applied === null) return null

  return getPostgrestConfig(ref)
}
