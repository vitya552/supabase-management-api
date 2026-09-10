import { env } from './env.js'
import { signJwtHS256 } from './jwt.js'
import {
  getStoredRealtimeConfig,
  mergeStoredRealtimeConfig,
  type StoredRealtimeConfig,
} from './store.js'

const TENANT_ID = 'realtime-dev'

const NUMERIC_TENANT_FIELDS = [
  'max_concurrent_users',
  'max_events_per_second',
  'max_bytes_per_second',
  'max_channels_per_client',
  'max_joins_per_second',
  'max_presence_events_per_second',
  'max_payload_size_in_kb',
] as const

const BOOLEAN_TENANT_FIELDS = ['private_only', 'suspend'] as const

const TENANT_FIELDS = [...NUMERIC_TENANT_FIELDS, ...BOOLEAN_TENANT_FIELDS] as const

type TenantField = (typeof TENANT_FIELDS)[number]

export type RealtimeConfig = Partial<Record<TenantField, number | boolean>>

type RealtimeTarget = { baseUrl: string; jwtSecret: string }

export const REALTIME_RECONCILE_INTERVAL_MS = 30_000

async function resolveTarget(ref: string): Promise<RealtimeTarget | null> {
  if (ref !== 'default' || !env.jwtSecret) return null
  return {
    baseUrl: `http://${env.realtimeHost}:${env.realtimePort}`,
    jwtSecret: env.jwtSecret,
  }
}

function adminToken(jwtSecret: string): string {
  const iat = Math.floor(Date.now() / 1000)
  return signJwtHS256({ role: 'service_role', iss: 'supabase', iat, exp: iat + 300 }, jwtSecret)
}

function isNumericField(field: TenantField): field is (typeof NUMERIC_TENANT_FIELDS)[number] {
  return (NUMERIC_TENANT_FIELDS as readonly string[]).includes(field)
}

function pickTenantFields(source: Record<string, unknown>): RealtimeConfig {
  const picked: RealtimeConfig = {}
  for (const field of TENANT_FIELDS) {
    const value = source[field]
    if (isNumericField(field)) {
      if (typeof value === 'number') picked[field] = value
    } else if (typeof value === 'boolean') {
      picked[field] = value
    }
  }
  return picked
}

export function validateRealtimeUpdates(updates: Record<string, unknown>): string | null {
  for (const field of TENANT_FIELDS) {
    const value = updates[field]
    if (value === undefined || value === null) continue
    if (isNumericField(field)) {
      if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
        return `${field} must be a positive integer`
      }
    } else if (typeof value !== 'boolean') {
      return `${field} must be a boolean`
    }
  }
  return null
}

async function fetchTenant(target: RealtimeTarget): Promise<RealtimeConfig | null> {
  const response = await fetch(`${target.baseUrl}/api/tenants/${TENANT_ID}`, {
    headers: { Authorization: `Bearer ${adminToken(target.jwtSecret)}` },
  }).catch(() => null)
  if (response === null || !response.ok) return null
  const body = (await response.json().catch(() => null)) as { data?: Record<string, unknown> } | null
  if (!body || typeof body.data !== 'object' || body.data === null) return null
  return pickTenantFields(body.data)
}

async function patchTenant(target: RealtimeTarget, tenant: RealtimeConfig): Promise<boolean> {
  const response = await fetch(`${target.baseUrl}/api/tenants/${TENANT_ID}`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${adminToken(target.jwtSecret)}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ tenant }),
  }).catch(() => null)
  return response !== null && response.ok
}

export function driftedFields(
  stored: StoredRealtimeConfig,
  live: RealtimeConfig
): RealtimeConfig {
  const drift: RealtimeConfig = {}
  for (const field of TENANT_FIELDS) {
    const wanted = stored[field]
    if (wanted === undefined) continue
    if (live[field] !== wanted) drift[field] = wanted
  }
  return drift
}

export async function reconcileRealtimeConfig(ref: string): Promise<RealtimeConfig | null> {
  const target = await resolveTarget(ref)
  if (target === null) return null
  const live = await fetchTenant(target)
  if (live === null) return null
  const stored = await getStoredRealtimeConfig(ref)
  if (stored === null) return live
  const drift = driftedFields(stored, live)
  if (Object.keys(drift).length === 0) return live
  if (!(await patchTenant(target, drift))) return live
  return (await fetchTenant(target)) ?? live
}

export async function getRealtimeConfig(ref: string): Promise<RealtimeConfig | null> {
  return reconcileRealtimeConfig(ref)
}

export async function updateRealtimeConfig(
  ref: string,
  updates: Record<string, unknown>
): Promise<RealtimeConfig | null> {
  const target = await resolveTarget(ref)
  if (target === null) return null
  const tenant = pickTenantFields(updates)
  delete tenant.suspend
  if (!(await patchTenant(target, tenant))) return null
  await mergeStoredRealtimeConfig(ref, tenant)
  return fetchTenant(target)
}

export function startRealtimeReconciler(
  refs: () => Promise<string[]>,
  intervalMs = REALTIME_RECONCILE_INTERVAL_MS
): NodeJS.Timeout {
  const run = async () => {
    for (const ref of await refs().catch(() => [])) {
      await reconcileRealtimeConfig(ref).catch(() => null)
    }
  }
  void run()
  const timer = setInterval(() => void run(), intervalMs)
  timer.unref()
  return timer
}
