import { lookup } from 'node:dns/promises'
import { mkdir, writeFile } from 'node:fs/promises'
import { isIP } from 'node:net'
import { dirname } from 'node:path'

import { env } from './env.js'
import { pool } from './store.js'

export type ThirdPartyIntegration = {
  id: string
  type: string
  oidc_issuer_url: string | null
  jwks_url: string | null
  custom_jwks: unknown
  resolved_jwks: unknown
  resolved_at: Date | null
  inserted_at: Date
  updated_at: Date
}

type Jwks = { keys: unknown[] }

function isJwks(value: unknown): value is Jwks {
  return (
    typeof value === 'object' &&
    value !== null &&
    Array.isArray((value as { keys?: unknown }).keys)
  )
}

const MAX_JWKS_BYTES = 256 * 1024

function isPrivateAddress(address: string): boolean {
  if (isIP(address) === 6) {
    const normalized = address.toLowerCase()
    return (
      normalized === '::1' ||
      normalized === '::' ||
      normalized.startsWith('fe80:') ||
      normalized.startsWith('fc') ||
      normalized.startsWith('fd') ||
      normalized.startsWith('::ffff:')
    )
  }
  const [a, b] = address.split('.').map(Number)
  if (a === 10 || a === 127 || a === 0) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  return a >= 224
}

/**
 * JWKS endpoints are operator supplied but fetched by a service that sits on
 * the internal docker network, so only public HTTP(S) hosts are allowed: a
 * loopback or private address would turn this into an SSRF into the stack.
 */
async function assertPublicUrl(rawUrl: string): Promise<URL> {
  let url: URL
  try {
    url = new URL(rawUrl)
  } catch {
    throw new Error(`invalid URL: ${rawUrl}`)
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('only http(s) URLs are supported')
  }

  const addresses = isIP(url.hostname)
    ? [url.hostname]
    : (await lookup(url.hostname, { all: true }).catch(() => [])).map((entry) => entry.address)
  if (addresses.length === 0) throw new Error(`could not resolve host: ${url.hostname}`)
  if (addresses.some(isPrivateAddress)) {
    throw new Error(`host ${url.hostname} resolves to a private address`)
  }
  return url
}

async function fetchJson(rawUrl: string): Promise<unknown> {
  const url = await assertPublicUrl(rawUrl)
  const response = await fetch(url, { signal: AbortSignal.timeout(10_000), redirect: 'error' })
  if (!response.ok) throw new Error(`GET ${url.href} returned ${response.status}`)
  const body = await response.text()
  if (body.length > MAX_JWKS_BYTES) throw new Error('JWKS response is too large')
  try {
    return JSON.parse(body)
  } catch {
    throw new Error(`GET ${url.href} did not return JSON`)
  }
}

/**
 * Resolves the JWKS for an integration: an explicit custom JWKS wins,
 * otherwise the JWKS URL is fetched, otherwise it is discovered through
 * the issuer's OIDC configuration.
 */
export async function resolveJwks(input: {
  oidc_issuer_url?: string | null
  jwks_url?: string | null
  custom_jwks?: unknown
}): Promise<Jwks> {
  if (input.custom_jwks != null) {
    if (!isJwks(input.custom_jwks)) throw new Error('custom_jwks must be a JWK Set ({ keys: [] })')
    return input.custom_jwks
  }
  if (input.jwks_url) {
    const jwks = await fetchJson(input.jwks_url)
    if (!isJwks(jwks)) throw new Error(`jwks_url did not return a JWK Set`)
    return jwks
  }
  if (input.oidc_issuer_url) {
    const issuer = input.oidc_issuer_url.replace(/\/$/, '')
    const discovery = await fetchJson(`${issuer}/.well-known/openid-configuration`)
    const jwksUri = (discovery as { jwks_uri?: unknown }).jwks_uri
    if (typeof jwksUri !== 'string') throw new Error('issuer discovery document has no jwks_uri')
    const jwks = await fetchJson(jwksUri)
    if (!isJwks(jwks)) throw new Error('issuer jwks_uri did not return a JWK Set')
    return jwks
  }
  throw new Error('one of oidc_issuer_url, jwks_url or custom_jwks is required')
}

export async function migrateThirdPartyAuth(): Promise<void> {
  await pool.query(`
    create table if not exists management.third_party_auth (
      id uuid primary key default gen_random_uuid(),
      oidc_issuer_url text,
      jwks_url text,
      custom_jwks jsonb,
      resolved_jwks jsonb,
      resolved_at timestamptz,
      inserted_at timestamptz not null default now(),
      updated_at timestamptz not null default now()
    );
    alter table management.third_party_auth
      add column if not exists project_ref text not null default 'default';
  `)
}

export async function listIntegrations(projectRef: string): Promise<ThirdPartyIntegration[]> {
  const { rows } = await pool.query(
    'select * from management.third_party_auth where project_ref = $1 order by inserted_at',
    [projectRef]
  )
  return rows.map(withType)
}

export async function getIntegration(
  projectRef: string,
  id: string
): Promise<ThirdPartyIntegration | null> {
  const { rows } = await pool.query(
    'select * from management.third_party_auth where project_ref = $1 and id = $2',
    [projectRef, id]
  )
  return rows[0] ? withType(rows[0]) : null
}

export async function createIntegration(
  projectRef: string,
  input: {
    oidc_issuer_url?: string | null
    jwks_url?: string | null
    custom_jwks?: unknown
  }
): Promise<ThirdPartyIntegration> {
  const jwks = await resolveJwks(input)
  const { rows } = await pool.query(
    `insert into management.third_party_auth
       (project_ref, oidc_issuer_url, jwks_url, custom_jwks, resolved_jwks, resolved_at)
     values ($1, $2, $3, $4::jsonb, $5::jsonb, now())
     returning *`,
    [
      projectRef,
      input.oidc_issuer_url ?? null,
      input.jwks_url ?? null,
      input.custom_jwks == null ? null : JSON.stringify(input.custom_jwks),
      JSON.stringify(jwks),
    ]
  )
  await syncThirdPartyJwks(projectRef)
  return withType(rows[0])
}

export async function deleteIntegration(
  projectRef: string,
  id: string
): Promise<ThirdPartyIntegration | null> {
  const { rows } = await pool.query(
    'delete from management.third_party_auth where project_ref = $1 and id = $2 returning *',
    [projectRef, id]
  )
  if (!rows[0]) return null
  await syncThirdPartyJwks(projectRef)
  return withType(rows[0])
}

/** Removes all integrations belonging to a project (deprovision). */
export async function deleteProjectIntegrations(projectRef: string): Promise<void> {
  await pool.query('delete from management.third_party_auth where project_ref = $1', [projectRef])
}

function withType(row: Omit<ThirdPartyIntegration, 'type'>): ThirdPartyIntegration {
  return { ...row, type: inferType(row.oidc_issuer_url) }
}

function inferType(issuer: string | null): string {
  if (!issuer) return 'custom'
  if (issuer.startsWith('https://securetoken.google.com/')) return 'firebase'
  if (issuer.includes('amazonaws.com')) return 'aws_cognito'
  if (issuer.includes('auth0.com')) return 'auth0'
  if (issuer.includes('.clerk.accounts.dev') || issuer.startsWith('https://clerk.')) return 'clerk'
  if (issuer.includes('workos.com')) return 'workos'
  return 'custom'
}

function base64Url(input: Buffer): string {
  return input.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function parseJsonOrNull(value: string): unknown {
  if (!value) return null
  try {
    return JSON.parse(value)
  } catch {
    return null
  }
}

/** The stack's own keys, trusted regardless of third-party integrations. */
function baselineKeys(): unknown[] {
  const configured = parseJsonOrNull(env.jwtJwks)
  if (isJwks(configured)) return configured.keys
  // A single JWK is also a valid PGRST_JWT_SECRET value upstream.
  if (configured && typeof configured === 'object' && 'kty' in configured) return [configured]
  if (!env.jwtSecret) {
    throw new Error('neither JWT_SECRET nor JWT_JWKS is configured on management-api')
  }
  return [{ kty: 'oct', k: base64Url(Buffer.from(env.jwtSecret, 'utf8')), alg: 'HS256' }]
}

/**
 * Materializes the trusted key set for PostgREST: the stack's own keys plus
 * every resolved third-party JWKS. The set is written to a file shared with
 * the postgrest container (`PGRST_JWT_SECRET=@<file>`) and picked up by a
 * config reload, so the symmetric secret never has to be stored in the
 * database catalog, which is readable by every role.
 */
export async function syncThirdPartyJwks(projectRef: string = 'default'): Promise<void> {
  const integrations = await listIntegrations(projectRef)

  const keys: unknown[] = [...(await baselineKeysFor(projectRef))]
  for (const integration of integrations) {
    if (isJwks(integration.resolved_jwks)) keys.push(...integration.resolved_jwks.keys)
  }

  const target = projectJwksFile(projectRef)
  if (!target) return
  await mkdir(dirname(target), { recursive: true })
  // Readable by any user inside the container because postgrest runs as a
  // different one; the file lives on a dedicated volume mounted only into this
  // service and postgrest, so it is no more exposed than the env var it
  // replaces.
  await writeFile(target, `${JSON.stringify({ keys })}\n`, {
    encoding: 'utf8',
    mode: 0o644,
  })

  // Older revisions of this service kept the key set in the role's config;
  // that setting takes precedence over the file, so it is cleared.
  await pool.query('alter role authenticator reset pgrst.jwt_secret').catch(() => undefined)
  await pool.query(`notify pgrst, 'reload config'`)
}

/** Where the trusted JWK set for PostgREST lives. */
function projectJwksFile(projectRef: string): string | null {
  if (projectRef === 'default') return env.postgrestJwksFile
  return null
}

/** The stack's own keys, trusted regardless of third-party integrations. */
async function baselineKeysFor(projectRef: string): Promise<unknown[]> {
  if (projectRef === 'default') return baselineKeys()
  return []
}
