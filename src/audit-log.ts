import { pool } from './store.js'

/**
 * Audit trail of mutating management API requests, backing the dashboard's
 * Account > Audit Logs page.
 */

export type AuditLogRecord = {
  id: number
  username: string
  method: string
  route: string
  status: number
  project_ref: string | null
  created_at: Date
}

export async function migrateAuditLogs(): Promise<void> {
  await pool.query(`
    create table if not exists management.audit_logs (
      id bigserial primary key,
      username text not null,
      method text not null,
      route text not null,
      status integer not null,
      project_ref text,
      created_at timestamptz not null default now()
    );
    create index if not exists audit_logs_created_at_idx
      on management.audit_logs (created_at);
  `)
}

export async function recordAuditLog(entry: {
  username: string
  method: string
  route: string
  status: number
  projectRef: string | null
}): Promise<void> {
  await pool.query(
    `insert into management.audit_logs (username, method, route, status, project_ref)
     values ($1, $2, $3, $4, $5)`,
    [entry.username, entry.method, entry.route, entry.status, entry.projectRef]
  )
}

export async function listAuditLogs(range: {
  start: Date
  end: Date
}): Promise<AuditLogRecord[]> {
  const { rows } = await pool.query(
    `select id, username, method, route, status, project_ref, created_at
     from management.audit_logs
     where created_at >= $1 and created_at <= $2
     order by created_at desc
     limit 1000`,
    [range.start, range.end]
  )
  return rows
}
