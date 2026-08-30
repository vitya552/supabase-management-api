import { createHmac } from 'node:crypto'

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url')
}

/** Signs a HS256 JWT, used to mint per-project anon/service_role API keys. */
export function signJwtHS256(
  payload: Record<string, unknown>,
  secret: string
): string {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const body = base64url(JSON.stringify(payload))
  const signature = createHmac('sha256', secret)
    .update(`${header}.${body}`)
    .digest('base64url')
  return `${header}.${body}.${signature}`
}

const TEN_YEARS_S = 10 * 365 * 24 * 60 * 60

export function mintApiKey(role: 'anon' | 'service_role', jwtSecret: string): string {
  const iat = Math.floor(Date.now() / 1000)
  return signJwtHS256({ role, iss: 'supabase', iat, exp: iat + TEN_YEARS_S }, jwtSecret)
}
