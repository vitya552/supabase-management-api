import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

import { env } from './env.js'

export const SESSION_COOKIE = 'sb-dashboard-session'
const SESSION_TTL_SECONDS = 8 * 60 * 60

export type DashboardSessionIdentity = {
  username: string
  role: 'owner' | 'admin' | 'developer'
}

/**
 * Signing key for session cookies. `DASHBOARD_SESSION_SECRET` keeps sessions
 * independent from the management token; without it a random per-process key
 * is used, which stays secure but invalidates sessions on restart.
 */
const sessionSecret =
  env.dashboardSessionSecret || `ephemeral:${randomBytes(32).toString('base64')}`

function hmac(payload: string): string {
  return createHmac('sha256', `dashboard-session:${sessionSecret}`).update(payload).digest('hex')
}

function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a)
  const bufB = Buffer.from(b)
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB)
}

export function createSessionToken(
  identity: DashboardSessionIdentity,
  now = Date.now()
): string {
  const payload = Buffer.from(
    JSON.stringify({
      exp: Math.floor(now / 1000) + SESSION_TTL_SECONDS,
      sub: identity.username,
      role: identity.role,
    })
  ).toString('base64url')
  return `v2.${payload}.${hmac(payload)}`
}

/** Returns the session's identity when the token is valid, else null. */
export function getSessionIdentity(
  token: string,
  now = Date.now()
): DashboardSessionIdentity | null {
  if (!token.startsWith('v2.')) return null
  const rest = token.slice(3)
  const dot = rest.indexOf('.')
  if (dot === -1) return null
  const payload = rest.slice(0, dot)
  const signature = rest.slice(dot + 1)
  if (!safeEqual(signature, hmac(payload))) return null
  try {
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
      exp?: unknown
      sub?: unknown
      role?: unknown
    }
    if (typeof parsed.exp !== 'number' || parsed.exp * 1000 < now) return null
    if (typeof parsed.sub !== 'string') return null
    if (parsed.role !== 'owner' && parsed.role !== 'admin' && parsed.role !== 'developer') {
      return null
    }
    return { username: parsed.sub, role: parsed.role }
  } catch {
    return null
  }
}

export function isValidSessionToken(token: string, now = Date.now()): boolean {
  return getSessionIdentity(token, now) !== null
}

/** `Set-Cookie` value for a fresh session, or for clearing it. */
export function sessionCookie(token: string | null): string {
  // `Secure` would make the cookie unusable on the plain-HTTP deployments the
  // self-hosted stack defaults to, so it follows the configured public URL.
  const secure = env.publicUrl.startsWith('https://') ? '; Secure' : ''
  const maxAge = token === null ? 0 : SESSION_TTL_SECONDS
  return `${SESSION_COOKIE}=${token ?? ''}; Path=/; HttpOnly; SameSite=Lax${secure}; Max-Age=${maxAge}`
}

export function getCookie(cookieHeader: string, name: string): string | null {
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim()
  }
  return null
}

export function isValidCredentials(username: string, password: string): boolean {
  if (!env.dashboardUsername || !env.dashboardPassword) return false
  return safeEqual(username, env.dashboardUsername) && safeEqual(password, env.dashboardPassword)
}

export function isValidBasicAuthHeader(authorization: string): boolean {
  if (!authorization.startsWith('Basic ')) return false
  const decoded = Buffer.from(authorization.slice('Basic '.length), 'base64').toString('utf8')
  const colon = decoded.indexOf(':')
  if (colon === -1) return false
  return isValidCredentials(decoded.slice(0, colon), decoded.slice(colon + 1))
}

/**
 * Only same-origin absolute paths are allowed as post-login redirects.
 * Backslashes are rejected because browsers treat `/\host` like `//host`.
 */
export function sanitizeRedirectPath(path: string | undefined): string {
  if (!path || !path.startsWith('/')) return '/'
  if (path.startsWith('//') || path.includes('\\')) return '/'
  return path
}

/**
 * Fixed-window limiter for dashboard logins, keyed by client address, so the
 * credentials cannot be brute-forced through the public gateway.
 */
const LOGIN_WINDOW_MS = 60_000
const LOGIN_MAX_ATTEMPTS = 10
const loginAttempts = new Map<string, { count: number; resetAt: number }>()

export function isLoginRateLimited(key: string, now = Date.now()): boolean {
  const entry = loginAttempts.get(key)
  if (entry === undefined || entry.resetAt <= now) {
    loginAttempts.set(key, { count: 1, resetAt: now + LOGIN_WINDOW_MS })
    if (loginAttempts.size > 10_000) {
      for (const [candidate, value] of loginAttempts) {
        if (value.resetAt <= now) loginAttempts.delete(candidate)
      }
    }
    return false
  }
  entry.count += 1
  return entry.count > LOGIN_MAX_ATTEMPTS
}

/** A successful login clears the attempt counter for that client. */
export function resetLoginRateLimit(key: string): void {
  loginAttempts.delete(key)
}
