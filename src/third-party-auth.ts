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

async function fetchJson(url: string): Promise<unknown> {
  const response = await fetch(url, { signal: AbortSignal.timeout(10_000) })
  if (!response.ok) throw new Error(`GET ${url} returned ${response.status}`)
  return response.json()
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
  `)
}

export async function listIntegrations(): Promise<ThirdPartyIntegration[]> {
  const { rows } = await pool.query(
    'select * from management.third_party_auth order by inserted_at'
  )
  return rows.map(withType)
}

export async function getIntegration(id: string): Promise<ThirdPartyIntegration | null> {
  const { rows } = await pool.query('select * from management.third_party_auth where id = $1', [
    id,
  ])
  return rows[0] ? withType(rows[0]) : null
}

export async function createIntegration(input: {
  oidc_issuer_url?: string | null
  jwks_url?: string | null
  custom_jwks?: unknown
}): Promise<ThirdPartyIntegration> {
  const jwks = await resolveJwks(input)
  const { rows } = await pool.query(
    `insert into management.third_party_auth
       (oidc_issuer_url, jwks_url, custom_jwks, resolved_jwks, resolved_at)
     values ($1, $2, $3::jsonb, $4::jsonb, now())
     returning *`,
    [
      input.oidc_issuer_url ?? null,
      input.jwks_url ?? null,
      input.custom_jwks == null ? null : JSON.stringify(input.custom_jwks),
      JSON.stringify(jwks),
    ]
  )
  await syncThirdPartyJwks()
  return withType(rows[0])
}

export async function deleteIntegration(id: string): Promise<ThirdPartyIntegration | null> {
  const { rows } = await pool.query(
    'delete from management.third_party_auth where id = $1 returning *',
    [id]
  )
  if (!rows[0]) return null
  await syncThirdPartyJwks()
  return withType(rows[0])
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

function quoteLiteral(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}

/**
 * Materializes the trusted key set for PostgREST: the stack's symmetric JWT
 * secret plus every resolved third-party JWKS, applied as reloadable
 * in-database config. With no integrations the setting is reset so the
 * container's env configuration applies again.
 */
export async function syncThirdPartyJwks(): Promise<void> {
  const integrations = await listIntegrations()

  if (integrations.length === 0) {
    await pool.query('alter role authenticator reset pgrst.jwt_secret')
    await pool.query(`notify pgrst, 'reload config'`)
    return
  }

  if (!env.jwtSecret) {
    throw new Error(
      'JWT_SECRET is not configured on management-api; cannot enable third-party auth safely'
    )
  }

  const keys: unknown[] = [
    { kty: 'oct', k: base64Url(Buffer.from(env.jwtSecret, 'utf8')), alg: 'HS256' },
  ]
  for (const integration of integrations) {
    if (isJwks(integration.resolved_jwks)) keys.push(...integration.resolved_jwks.keys)
  }

  await pool.query(
    `alter role authenticator set pgrst.jwt_secret = ${quoteLiteral(JSON.stringify({ keys }))}`
  )
  await pool.query(`notify pgrst, 'reload config'`)
}
