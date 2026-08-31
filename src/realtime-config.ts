import { env } from './env.js'
import { signJwtHS256 } from './jwt.js'

/** Tenant id seeded by Realtime's SEED_SELF_HOST (also the Host prefix). */
const TENANT_ID = 'realtime-dev'

/** Tenant fields Realtime's admin API accepts that the dashboard exposes. */
const TENANT_FIELDS = [
  'max_concurrent_users',
  'max_events_per_second',
  'max_bytes_per_second',
  'max_channels_per_client',
  'max_joins_per_second',
  'max_presence_events_per_second',
  'max_payload_size_in_kb',
  'private_only',
  'suspend',
] as const

type TenantField = (typeof TENANT_FIELDS)[number]

export type RealtimeConfig = Partial<Record<TenantField, unknown>>

type RealtimeTarget = { baseUrl: string; jwtSecret: string }

/** Resolves the stack's Realtime service and admin credentials. */
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

function pickTenantFields(source: Record<string, unknown>): RealtimeConfig {
  const picked: RealtimeConfig = {}
  for (const field of TENANT_FIELDS) {
    if (source[field] !== undefined && source[field] !== null) picked[field] = source[field]
  }
  return picked
}

/** Current tenant limits, or null when Realtime is unavailable for the ref. */
export async function getRealtimeConfig(ref: string): Promise<RealtimeConfig | null> {
  const target = await resolveTarget(ref)
  if (target === null) return null
  const response = await fetch(`${target.baseUrl}/api/tenants/${TENANT_ID}`, {
    headers: { Authorization: `Bearer ${adminToken(target.jwtSecret)}` },
  }).catch(() => null)
  if (response === null || !response.ok) return null
  const body = (await response.json().catch(() => null)) as { data?: Record<string, unknown> } | null
  if (!body || typeof body.data !== 'object' || body.data === null) return null
  return pickTenantFields(body.data)
}

/**
 * Applies the supported subset of the dashboard's realtime settings to the
 * project's tenant. Returns the updated config or null when unavailable.
 */
export async function updateRealtimeConfig(
  ref: string,
  updates: Record<string, unknown>
): Promise<RealtimeConfig | null> {
  const target = await resolveTarget(ref)
  if (target === null) return null
  const tenant = pickTenantFields(updates)
  // Suspending is not supported: the seeded self-host tenant ignores it.
  delete tenant.suspend
  const response = await fetch(`${target.baseUrl}/api/tenants/${TENANT_ID}`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${adminToken(target.jwtSecret)}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ tenant }),
  }).catch(() => null)
  if (response === null || !response.ok) return null
  return getRealtimeConfig(ref)
}
