import { createHmac, timingSafeEqual } from 'node:crypto'

import { env } from './env.js'

export const SESSION_COOKIE = 'sb-dashboard-session'
const SESSION_TTL_SECONDS = 8 * 60 * 60

function hmac(payload: string): string {
  return createHmac('sha256', `dashboard-session:${env.apiToken}`).update(payload).digest('hex')
}

function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a)
  const bufB = Buffer.from(b)
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB)
}

export function createSessionToken(now = Date.now()): string {
  const expiresAt = String(Math.floor(now / 1000) + SESSION_TTL_SECONDS)
  return `${expiresAt}.${hmac(expiresAt)}`
}

export function isValidSessionToken(token: string, now = Date.now()): boolean {
  const dot = token.indexOf('.')
  if (dot === -1) return false
  const expiresAt = token.slice(0, dot)
  const signature = token.slice(dot + 1)
  if (!/^\d+$/.test(expiresAt)) return false
  if (Number(expiresAt) * 1000 < now) return false
  return safeEqual(signature, hmac(expiresAt))
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

/** Only same-origin absolute paths are allowed as post-login redirects. */
export function sanitizeRedirectPath(path: string | undefined): string {
  if (!path || !path.startsWith('/') || path.startsWith('//')) return '/'
  return path
}
