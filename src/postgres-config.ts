import pg from 'pg'

import { env } from './env.js'
import { pool } from './store.js'

/**
 * GUCs managed through the platform `config/database/postgres` endpoint
 * (`PostgresConfigResponse` in api-types), applied with `ALTER SYSTEM` +
 * `pg_reload_conf()`. Settings with a postmaster context only take effect
 * after the database container restarts; they are reported in
 * `restart_required`.
 */
const MANAGED_GUCS: Record<string, 'string' | 'number' | 'boolean'> = {
  checkpoint_timeout: 'string',
  'cron.log_statement': 'boolean',
  effective_cache_size: 'string',
  hot_standby_feedback: 'boolean',
  log_autovacuum_min_duration: 'string',
  log_checkpoints: 'boolean',
  log_connections: 'boolean',
  log_disconnections: 'boolean',
  log_duration: 'boolean',
  log_lock_waits: 'boolean',
  log_recovery_conflict_waits: 'boolean',
  log_replication_commands: 'boolean',
  log_startup_progress_interval: 'string',
  log_temp_files: 'string',
  logical_decoding_work_mem: 'string',
  maintenance_work_mem: 'string',
  max_connections: 'number',
  max_locks_per_transaction: 'number',
  max_logical_replication_workers: 'number',
  max_parallel_maintenance_workers: 'number',
  max_parallel_workers: 'number',
  max_parallel_workers_per_gather: 'number',
  max_replication_slots: 'number',
  max_slot_wal_keep_size: 'string',
  max_standby_archive_delay: 'string',
  max_standby_streaming_delay: 'string',
  max_sync_workers_per_subscription: 'number',
  max_wal_senders: 'number',
  max_wal_size: 'string',
  max_worker_processes: 'number',
  session_replication_role: 'string',
  shared_buffers: 'string',
  statement_timeout: 'string',
  track_activity_query_size: 'string',
  track_commit_timestamp: 'boolean',
  wal_keep_size: 'string',
  wal_sender_timeout: 'string',
  work_mem: 'string',
}

export type PostgresConfigValue = string | number | boolean

export function isManagedGuc(name: string): boolean {
  return Object.prototype.hasOwnProperty.call(MANAGED_GUCS, name)
}

export function validateGucValue(name: string, value: unknown): string | null {
  const type = MANAGED_GUCS[name]
  if (!type) return `unsupported setting: ${name}`
  if (type === 'boolean' && typeof value !== 'boolean') return `${name} must be a boolean`
  if (type === 'number' && typeof value !== 'number') return `${name} must be a number`
  if (type === 'string' && typeof value !== 'string' && typeof value !== 'number') {
    return `${name} must be a string`
  }
  return null
}

/** The superuser connection string for the stack's Postgres, or null. */
async function databaseUrlFor(ref: string): Promise<string | null> {
  if (ref === 'default') return env.databaseUrl
  return null
}

export async function getPostgresConfig(
  ref: string
): Promise<Record<string, PostgresConfigValue> | null> {
  const dbUrl = await databaseUrlFor(ref)
  if (!dbUrl) return null
  // A fresh connection is used because backend-context settings (e.g.
  // log_connections) are fixed at connection start, so long-lived pooled
  // sessions would report stale values.
  const client = new pg.Client({ connectionString: dbUrl })
  await client.connect()
  let rows: { name: string; setting: string; unit: string | null }[]
  try {
    const result = await client.query<{ name: string; setting: string; unit: string | null }>(
      `select name, setting, unit from pg_settings where name = any($1)`,
      [Object.keys(MANAGED_GUCS)]
    )
    rows = result.rows
  } finally {
    await client.end()
  }

  const config: Record<string, PostgresConfigValue> = {}
  for (const row of rows) {
    const type = MANAGED_GUCS[row.name]
    if (type === 'boolean') config[row.name] = row.setting === 'on'
    else if (type === 'number') config[row.name] = Number(row.setting)
    else config[row.name] = row.unit ? `${row.setting}${row.unit}` : row.setting
  }
  return config
}

function quoteLiteral(value: PostgresConfigValue): string {
  return `'${String(value).replace(/'/g, "''")}'`
}

export async function updatePostgresConfig(
  ref: string,
  patch: Record<string, PostgresConfigValue>
): Promise<{ config: Record<string, PostgresConfigValue>; restart_required: string[] } | null> {
  const dbUrl = await databaseUrlFor(ref)
  if (!dbUrl) return null
  const isPooled = ref === 'default'
  const pooledClient = isPooled ? await pool.connect() : null
  const directClient = isPooled ? null : new pg.Client({ connectionString: dbUrl })
  if (directClient) await directClient.connect()
  const client = pooledClient ?? directClient!
  let pendingRestart: string[]
  try {
    for (const [name, value] of Object.entries(patch)) {
      // ALTER SYSTEM cannot run inside a transaction block.
      await client.query(`alter system set ${name} = ${quoteLiteral(value)}`)
    }
    await client.query(`select pg_reload_conf()`)
    // The SIGHUP reload is asynchronous; give the postmaster a moment so the
    // config read below reflects the new values.
    await client.query(`select pg_sleep(0.2)`)
    const { rows } = await client.query<{ name: string }>(
      `select name from pg_settings where pending_restart`
    )
    pendingRestart = rows.map((row) => row.name)
  } finally {
    if (pooledClient) pooledClient.release()
    if (directClient) await directClient.end().catch(() => undefined)
  }

  const config = await getPostgresConfig(ref)
  if (config === null) return null
  return { config, restart_required: pendingRestart }
}
