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

export function renderLoginPage(options: { redirectTo: string; errorMessage?: string }): string {
  const errorHtml = options.errorMessage
    ? `<p class="error">${escapeHtml(options.errorMessage)}</p>`
    : ''
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sign in | Supabase</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #121212; color: #ededed;
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  .card {
    width: 100%; max-width: 360px; padding: 32px;
    background: #1c1c1c; border: 1px solid #2e2e2e; border-radius: 8px;
  }
  .logo { display: flex; align-items: center; gap: 10px; margin-bottom: 24px; }
  .logo svg { width: 24px; height: 24px; }
  .logo span { font-size: 16px; font-weight: 600; }
  h1 { font-size: 14px; font-weight: 400; color: #a0a0a0; margin: 0 0 24px; }
  label { display: block; font-size: 12px; color: #a0a0a0; margin: 0 0 6px; }
  input {
    width: 100%; padding: 8px 12px; margin-bottom: 16px;
    background: #121212; color: #ededed; border: 1px solid #2e2e2e; border-radius: 6px;
    font-size: 14px;
  }
  input:focus { outline: none; border-color: #3ecf8e; }
  button {
    width: 100%; padding: 9px 12px; margin-top: 4px;
    background: #006239; color: #fff; border: 1px solid #3ecf8e; border-radius: 6px;
    font-size: 14px; cursor: pointer;
  }
  button:hover { background: #007a47; }
  .error {
    background: #2a1215; border: 1px solid #58151c; color: #f4a8ad;
    padding: 8px 12px; border-radius: 6px; font-size: 13px; margin: 0 0 16px;
  }
</style>
</head>
<body>
<main class="card">
  <div class="logo">
    <svg viewBox="0 0 109 113" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M63.708 110.284c-2.86 3.601-8.658 1.628-8.727-2.97l-1.007-67.251h45.22c8.19 0 12.758 9.46 7.665 15.874l-43.151 54.347Z" fill="#3ECF8E"/>
      <path d="M45.317 2.071c2.86-3.601 8.657-1.628 8.726 2.97l.442 67.251H9.83c-8.19 0-12.759-9.46-7.665-15.875L45.317 2.072Z" fill="#3ECF8E"/>
    </svg>
    <span>Supabase</span>
  </div>
  <h1>Sign in to your dashboard</h1>
  ${errorHtml}
  <form method="post" action="/dashboard-auth/login">
    <input type="hidden" name="redirect_to" value="${escapeHtml(options.redirectTo)}" />
    <label for="username">Username</label>
    <input id="username" name="username" autocomplete="username" autofocus required />
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required />
    <button type="submit">Sign in</button>
  </form>
</main>
</body>
</html>`
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}
