import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { logger } from 'hono/logger'
import { createHash, timingSafeEqual } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import pg from 'pg'

import { AUTH_CONFIG_KEYS } from './auth-config-keys.js'
import { baselineConfig } from './baseline.js'
import {
  createMfaPendingToken,
  createSessionToken,
  type DashboardSessionIdentity,
  getCookie,
  getMfaPendingIdentity,
  getSessionIdentity,
  isLoginRateLimited,
  isValidBasicAuthHeader,
  isValidCredentials,
  isValidSessionToken,
  resetLoginRateLimit,
  sanitizeRedirectPath,
  sessionCookie,
  SESSION_COOKIE,
} from './dashboard-auth.js'
import {
  acceptInvitation,
  createDashboardUser,
  createInvitation,
  createUserFactor,
  DASHBOARD_ROLES,
  type DashboardRole,
  deleteDashboardUser,
  deleteInvitation,
  deleteUserFactor,
  getDashboardProfile,
  getDashboardUser,
  getUserFactorSecret,
  hasVerifiedFactor,
  listDashboardUsers,
  listInvitations,
  listUserFactors,
  listUsernamesWithVerifiedFactors,
  listVerifiedFactorSecrets,
  markFactorVerified,
  migrateDashboardUsers,
  updateDashboardUserPassword,
  updateDashboardUserProfile,
  updateDashboardUserRole,
  verifyDashboardUser,
} from './dashboard-users.js'
import { listAuditLogs, migrateAuditLogs, recordAuditLog } from './audit-log.js'
import { renderReactEmail } from './emails.js'
import { generateTotpSecret, totpUri, verifyTotpCode } from './totp.js'
import { defaultAuthConfig } from './gotrue-defaults.js'
import { defaultReactEmailSource } from './react-email-defaults.js'
import { env } from './env.js'
import { syncEnvFile, templateTypeFromConfigKey } from './envfile.js'
import {
  deleteFunctionFiles,
  type FunctionFile,
  isValidSlug,
  listFunctionFiles,
  writeFunctionFiles,
  writeManifestFile,
  writeSecretsFile,
} from './functions.js'
import { isSmtpConfigured, sendInvitationEmail } from './mailer.js'
import { getRealtimeConfig, updateRealtimeConfig } from './realtime-config.js'
import { getS3ProtocolInfo, getStorageConfig } from './storage-config.js'
import {
  createOrganization,
  getProject,
  listOrganizations,
  updateOrganization,
  listProjects,
  migrateProjects,
  type ProjectRecord,
} from './projects-store.js'
import {
  getPostgresConfig,
  isManagedGuc,
  type PostgresConfigValue,
  updatePostgresConfig,
  validateGucValue,
} from './postgres-config.js'
import { getPostgrestConfig, updatePostgrestConfig } from './postgrest.js'
import {
  type ConfigValue,
  deleteConfig,
  deleteEdgeFunction,
  deleteEmailTemplate,
  deleteFunctionSecrets,
  type EdgeFunctionRecord,
  getAllConfig,
  getEdgeFunction,
  getEdgeFunctions,
  getEmailTemplate,
  getFunctionSecrets,
  migrate,
  updateEdgeFunction,
  upsertConfig,
  upsertEdgeFunction,
  upsertEmailTemplate,
  upsertFunctionSecrets,
} from './store.js'
import {
  createIntegration,
  deleteIntegration,
  getIntegration,
  listIntegrations,
  migrateThirdPartyAuth,
  syncThirdPartyJwks,
  type ThirdPartyIntegration,
} from './third-party-auth.js'

const app = new Hono()

app.use(logger())

app.get('/health', (c) => c.json({ status: 'ok' }))

/**
 * Rendered email templates, fetched by GoTrue via MAILER_TEMPLATES_* URLs.
 * Unauthenticated by design: only reachable on the internal docker network.
 */
app.get('/templates/:type', async (c) => {
  const ref = c.req.query('ref') ?? 'default'
  const template = await getEmailTemplate(ref, c.req.param('type'))
  if (!template) return c.text('template not found', 404)
  return c.html(template.rendered_html)
})

function isValidApiToken(authorization: string): boolean {
  const expected = Buffer.from(`Bearer ${env.apiToken}`)
  const provided = Buffer.from(authorization)
  return expected.length === provided.length && timingSafeEqual(expected, provided)
}

// Everything under /platform requires the management token.
app.use('/platform/*', async (c, next) => {
  if (!isValidApiToken(c.req.header('authorization') ?? '')) {
    return c.json({ message: 'Unauthorized' }, 401)
  }
  await next()
})

// Records every mutating request for the account audit log page.
app.use('/platform/*', async (c, next) => {
  await next()
  const method = c.req.method
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return
  const identity = await requestIdentity(c).catch(() => null)
  const username = identity && identity !== 'invalid' ? identity.username : 'service'
  const route = c.req.path
  const refMatch = route.match(/^\/platform\/projects\/([^/]+)/)
  await recordAuditLog({
    username,
    method,
    route,
    status: c.res.status,
    projectRef: refMatch ? refMatch[1] : null,
  }).catch((err) => console.error('failed to record audit log:', err))
})

/**
 * Dashboard identity of the request, taken from the forwarded session cookie
 * (Studio forwards it on proxied calls). Requests without a session cookie
 * are direct token-authenticated API calls and act with full (owner) rights.
 * Identities are resolved against the users table on every request, so
 * deleting a user (or a user leaving the team) revokes their sessions
 * immediately and role changes take effect right away; a cookie whose user no
 * longer exists resolves to `'invalid'` and never authorizes anything.
 */
async function requestIdentity(c: {
  req: { header: (name: string) => string | undefined }
}): Promise<DashboardSessionIdentity | 'invalid' | null> {
  const token = getCookie(c.req.header('cookie') ?? '', SESSION_COOKIE)
  if (!token) return null
  const session = getSessionIdentity(token)
  if (!session) return 'invalid'
  if (env.dashboardUsername && session.username === env.dashboardUsername) {
    return { username: session.username, role: 'owner' }
  }
  const user = await getDashboardUser(session.username)
  if (!user) return 'invalid'
  return { username: user.username, role: user.role }
}

/** True when the request may perform owner-only actions (managing owners). */
async function isOwner(c: {
  req: { header: (name: string) => string | undefined }
}): Promise<boolean> {
  const identity = await requestIdentity(c)
  if (identity === 'invalid') return false
  return identity === null || identity.role === 'owner'
}

/** True when the request may perform owner/admin-only actions. */
async function canAdminister(c: {
  req: { header: (name: string) => string | undefined }
}): Promise<boolean> {
  const identity = await requestIdentity(c)
  if (identity === 'invalid') return false
  return identity === null || identity.role === 'owner' || identity.role === 'admin'
}

function validateConfigPayload(payload: Record<string, unknown>): {
  valid: Record<string, ConfigValue>
  errors: string[]
} {
  const valid: Record<string, ConfigValue> = {}
  const errors: string[] = []
  for (const [key, value] of Object.entries(payload)) {
    const expected = AUTH_CONFIG_KEYS[key]
    if (expected === undefined) {
      errors.push(`unknown config key: ${key}`)
      continue
    }
    if (value === null) {
      valid[key] = null
      continue
    }
    if (typeof value === expected && (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean')) {
      valid[key] = value
      continue
    }
    errors.push(`config key ${key} must be a ${expected}`)
  }
  return { valid, errors }
}

/** Resolves which project an auth config request targets. */
async function resolveAuthRef(ref: string): Promise<string | null> {
  return ref === 'default' ? 'default' : null
}

async function applyConfigPatch(ref: string, payload: Record<string, unknown>) {
  const { valid, errors } = validateConfigPayload(payload)
  if (errors.length > 0) return { errors }

  // Template content updates also materialize a rendered template that
  // GoTrue fetches over HTTP.
  for (const [key, value] of Object.entries(valid)) {
    const templateType = templateTypeFromConfigKey(key)
    if (!templateType) continue
    if (value === null) {
      await deleteEmailTemplate(ref, templateType)
    } else if (typeof value === 'string') {
      await upsertEmailTemplate(ref, {
        template_type: templateType,
        source: value,
        source_format: 'html',
        rendered_html: value,
      })
    }
  }

  await upsertConfig(ref, valid)
  await syncEnvFile()
  return { errors: [] as string[] }
}

async function currentConfig(ref: string) {
  const stored = await getAllConfig(ref)
  const templatesCustom: Record<string, boolean> = {}
  const subjectsCustom: Record<string, boolean> = {}
  for (const key of Object.keys(stored)) {
    if (/^MAILER_TEMPLATES_.+_CONTENT$/.test(key)) templatesCustom[key] = true
    else if (key.startsWith('MAILER_SUBJECTS_')) subjectsCustom[key] = true
  }
  const merged = {
    ...baselineConfig(),
    ...stored,
  }
  return {
    ...defaultAuthConfig(),
    ...merged,
    MAILER_TEMPLATES_CUSTOM_CONTENTS: templatesCustom,
    MAILER_SUBJECTS_CUSTOM_CONTENTS: subjectsCustom,
  }
}

app.get('/platform/auth/:ref/config', async (c) => {
  const ref = await resolveAuthRef(c.req.param('ref'))
  if (!ref) return c.json({ message: 'Auth is not available for this project' }, 404)
  return c.json(await currentConfig(ref))
})

app.patch('/platform/auth/:ref/config', async (c) => {
  const ref = await resolveAuthRef(c.req.param('ref'))
  if (!ref) return c.json({ message: 'Auth is not available for this project' }, 404)
  const payload = await c.req.json<Record<string, unknown>>()
  const { errors } = await applyConfigPatch(ref, payload)
  if (errors.length > 0) return c.json({ message: errors.join('; ') }, 400)
  return c.json(await currentConfig(ref))
})

app.patch('/platform/auth/:ref/config/hooks', async (c) => {
  const ref = await resolveAuthRef(c.req.param('ref'))
  if (!ref) return c.json({ message: 'Auth is not available for this project' }, 404)
  const payload = await c.req.json<Record<string, unknown>>()
  const { errors } = await applyConfigPatch(ref, payload)
  if (errors.length > 0) return c.json({ message: errors.join('; ') }, 400)
  return c.json(await currentConfig(ref))
})

/**
 * Template types GoTrue knows about, derived from the config keys it accepts.
 * Anything else is rejected so a template name can never reach the generated
 * env file, whose lines are keyed by it.
 */
const TEMPLATE_TYPES = new Set(
  Object.keys(AUTH_CONFIG_KEYS)
    .map(templateTypeFromConfigKey)
    .filter((type): type is string => type !== null)
)

function templateParam(c: { req: { param: (name: string) => string } }): string | null {
  const template = c.req.param('template').toLowerCase()
  return TEMPLATE_TYPES.has(template) ? template : null
}

app.post('/platform/auth/:ref/templates/:template/reset', async (c) => {
  const ref = await resolveAuthRef(c.req.param('ref'))
  if (!ref) return c.json({ message: 'Auth is not available for this project' }, 404)
  const template = templateParam(c)
  if (!template) return c.json({ message: 'unknown template type' }, 400)
  await deleteEmailTemplate(ref, template)
  await deleteConfig(ref, [
    `MAILER_TEMPLATES_${template.toUpperCase()}_CONTENT`,
    `MAILER_SUBJECTS_${template.toUpperCase()}`,
  ])
  await syncEnvFile()
  return c.json(await currentConfig(ref))
})

/**
 * React email templates (self-hosted extension endpoint). Accepts TSX
 * source with a react-email component as its default export, renders it to
 * HTML and wires it up as the GoTrue template for the given type.
 */
app.put('/platform/auth/:ref/templates/:template/react', async (c) => {
  const ref = await resolveAuthRef(c.req.param('ref'))
  if (!ref) return c.json({ message: 'Auth is not available for this project' }, 404)
  const template = templateParam(c)
  if (!template) return c.json({ message: 'unknown template type' }, 400)
  const { source } = await c.req.json<{ source?: string }>()
  if (!source || typeof source !== 'string') {
    return c.json({ message: 'body must contain a `source` string' }, 400)
  }

  let renderedHtml: string
  try {
    renderedHtml = await renderReactEmail(source)
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return c.json({ message: `failed to render template: ${message}` }, 400)
  }

  await upsertEmailTemplate(ref, {
    template_type: template,
    source,
    source_format: 'react',
    rendered_html: renderedHtml,
  })
  await upsertConfig(ref, {
    [`MAILER_TEMPLATES_${template.toUpperCase()}_CONTENT`]: renderedHtml,
  })
  await syncEnvFile()
  return c.json({ template_type: template, rendered_html: renderedHtml })
})

app.get('/platform/auth/:ref/templates/:template/react', async (c) => {
  const ref = await resolveAuthRef(c.req.param('ref'))
  if (!ref) return c.json({ message: 'Auth is not available for this project' }, 404)
  const type = templateParam(c)
  if (!type) return c.json({ message: 'unknown template type' }, 400)
  const template = await getEmailTemplate(ref, type)
  if (template && template.source_format === 'react') {
    return c.json({ ...template, is_default: false })
  }
  const source = defaultReactEmailSource(type)
  if (!source) return c.json({ message: 'react template not found' }, 404)
  return c.json({
    template_type: type,
    source,
    source_format: 'react',
    rendered_html: null,
    is_default: true,
  })
})

// -- Edge Functions -----------------------------------------------------

const MAX_FUNCTION_FILES = 100
const MAX_FUNCTION_BYTES = 10 * 1024 * 1024

/**
 * Resolves the on-disk functions directory for a project. The default stack
 * uses the shared FUNCTIONS_DIR volume.
 */
async function resolveFunctionsDir(
  ref: string
): Promise<{ dir: string } | { message: string; status: 404 | 501 }> {
  if (ref !== 'default') return { message: `project ${ref} not found`, status: 404 }
  if (!env.functionsDir) {
    return { message: 'edge functions management is not configured (FUNCTIONS_DIR)', status: 501 }
  }
  return { dir: env.functionsDir }
}

/** Republishes per-function settings the `main` dispatcher enforces. */
async function syncFunctionManifest(ref: string, dir: string) {
  await writeManifestFile(dir, await getEdgeFunctions(ref))
}

function functionResponse(fn: EdgeFunctionRecord) {
  return {
    id: fn.slug,
    slug: fn.slug,
    name: fn.name,
    version: fn.version,
    status: 'ACTIVE',
    verify_jwt: fn.verify_jwt,
    entrypoint_path: fn.entrypoint_path ?? undefined,
    import_map_path: fn.import_map_path ?? undefined,
    created_at: new Date(fn.created_at).getTime(),
    updated_at: new Date(fn.updated_at).getTime(),
  }
}

app.get('/platform/projects/:ref/functions', async (c) => {
  const ref = c.req.param('ref')
  const resolved = await resolveFunctionsDir(ref)
  if ('status' in resolved) return c.json({ message: resolved.message }, resolved.status)
  return c.json((await getEdgeFunctions(ref)).map(functionResponse))
})

app.post('/platform/projects/:ref/functions/deploy', async (c) => {
  const ref = c.req.param('ref')
  const resolved = await resolveFunctionsDir(ref)
  if ('status' in resolved) return c.json({ message: resolved.message }, resolved.status)
  const slug = (c.req.query('slug') ?? '').toLowerCase()
  if (!isValidSlug(slug)) return c.json({ message: `invalid function slug: ${slug}` }, 400)

  const form = await c.req.formData()
  const metadataRaw = form.get('metadata')
  let metadata: {
    name?: string
    verify_jwt?: boolean
    entrypoint_path?: string
    import_map_path?: string
  } = {}
  if (typeof metadataRaw === 'string') {
    try {
      metadata = JSON.parse(metadataRaw)
    } catch {
      return c.json({ message: 'metadata must be valid JSON' }, 400)
    }
  }

  const files: FunctionFile[] = []
  let totalBytes = 0
  for (const entry of form.getAll('file')) {
    if (typeof entry === 'string') continue
    if (files.length >= MAX_FUNCTION_FILES) {
      return c.json({ message: `a function may not have more than ${MAX_FUNCTION_FILES} files` }, 413)
    }
    const content = await entry.text()
    totalBytes += Buffer.byteLength(content, 'utf8')
    if (totalBytes > MAX_FUNCTION_BYTES) {
      return c.json({ message: 'function bundle is too large' }, 413)
    }
    files.push({ name: entry.name, content })
  }
  if (files.length === 0) return c.json({ message: 'at least one file is required' }, 400)

  try {
    await writeFunctionFiles(resolved.dir, slug, files)
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return c.json({ message }, 400)
  }

  const fn = await upsertEdgeFunction(ref, {
    slug,
    name: metadata.name ?? slug,
    verify_jwt: metadata.verify_jwt ?? true,
    entrypoint_path: metadata.entrypoint_path ?? null,
    import_map_path: metadata.import_map_path ?? null,
  })
  await syncFunctionManifest(ref, resolved.dir)
  return c.json(functionResponse(fn))
})

app.get('/platform/projects/:ref/functions/:slug', async (c) => {
  const ref = c.req.param('ref')
  const resolved = await resolveFunctionsDir(ref)
  if ('status' in resolved) return c.json({ message: resolved.message }, resolved.status)
  const fn = await getEdgeFunction(ref, c.req.param('slug'))
  if (!fn) return c.json({ message: 'function not found' }, 404)
  return c.json(functionResponse(fn))
})

app.get('/platform/projects/:ref/functions/:slug/files', async (c) => {
  const ref = c.req.param('ref')
  const resolved = await resolveFunctionsDir(ref)
  if ('status' in resolved) return c.json({ message: resolved.message }, resolved.status)
  const slug = c.req.param('slug')
  if (!isValidSlug(slug)) return c.json({ message: `invalid function slug: ${slug}` }, 400)
  const fn = await getEdgeFunction(ref, slug)
  if (!fn) return c.json({ message: 'function not found' }, 404)
  const entries = await listFunctionFiles(resolved.dir, slug)
  const files = await Promise.all(
    entries.map(async (entry) => ({
      name: entry.relativePath,
      content: await readFile(entry.absolutePath, 'utf8'),
    }))
  )
  return c.json({ files })
})

app.patch('/platform/projects/:ref/functions/:slug', async (c) => {
  const ref = c.req.param('ref')
  const resolved = await resolveFunctionsDir(ref)
  if ('status' in resolved) return c.json({ message: resolved.message }, resolved.status)
  const payload = await c.req.json<{ name?: string; verify_jwt?: boolean }>()
  const fn = await updateEdgeFunction(ref, c.req.param('slug'), payload)
  if (!fn) return c.json({ message: 'function not found' }, 404)
  await syncFunctionManifest(ref, resolved.dir)
  return c.json(functionResponse(fn))
})

app.delete('/platform/projects/:ref/functions/:slug', async (c) => {
  const ref = c.req.param('ref')
  const resolved = await resolveFunctionsDir(ref)
  if ('status' in resolved) return c.json({ message: resolved.message }, resolved.status)
  const slug = c.req.param('slug')
  if (!isValidSlug(slug)) return c.json({ message: `invalid function slug: ${slug}` }, 400)
  await deleteFunctionFiles(resolved.dir, slug)
  await deleteEdgeFunction(ref, slug)
  await syncFunctionManifest(ref, resolved.dir)
  return c.json({ slug })
})

// -- Edge Function secrets ----------------------------------------------

async function syncSecretsFile(ref: string, dir: string) {
  const secrets = await getFunctionSecrets(ref)
  const out: Record<string, string> = {}
  for (const secret of secrets) out[secret.name] = secret.value
  await writeSecretsFile(dir, out)
}

app.get('/platform/projects/:ref/secrets', async (c) => {
  const ref = c.req.param('ref')
  const resolved = await resolveFunctionsDir(ref)
  if ('status' in resolved) return c.json({ message: resolved.message }, resolved.status)
  const secrets = await getFunctionSecrets(ref)
  // Secret values are write-only through the API: the list response exposes
  // a SHA256 digest of each value, matching the hosted platform contract.
  return c.json(
    secrets.map((secret) => ({
      name: secret.name,
      value: createHash('sha256').update(secret.value).digest('hex'),
      updated_at: new Date(secret.updated_at).toISOString(),
    }))
  )
})

const SECRET_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/

/**
 * Names the edge runtime relies on. Managed secrets are merged over the
 * runtime's own environment, so allowing these would let a secret repoint
 * functions at another database or forge the stack's tokens.
 */
const RESERVED_SECRET_NAMES = new Set([
  'SUPABASE_URL',
  'SUPABASE_ANON_KEY',
  'SUPABASE_SERVICE_ROLE_KEY',
  'SUPABASE_PUBLISHABLE_KEY',
  'SUPABASE_SECRET_KEY',
  'SUPABASE_DB_URL',
  'SUPABASE_JWKS',
  'SUPABASE_FUNCTION_SLUG',
  'JWT_SECRET',
  'VERIFY_JWT',
  'PATH',
  'LD_PRELOAD',
  'NODE_OPTIONS',
])

app.post('/platform/projects/:ref/secrets', async (c) => {
  const ref = c.req.param('ref')
  const resolved = await resolveFunctionsDir(ref)
  if ('status' in resolved) return c.json({ message: resolved.message }, resolved.status)
  const payload = await c.req.json<Array<{ name?: string; value?: string }>>()
  if (!Array.isArray(payload)) {
    return c.json({ message: 'body must be an array of { name, value }' }, 400)
  }
  const secrets: Array<{ name: string; value: string }> = []
  for (const entry of payload) {
    if (
      !entry ||
      typeof entry.name !== 'string' ||
      typeof entry.value !== 'string' ||
      !SECRET_NAME_RE.test(entry.name)
    ) {
      return c.json({ message: 'each secret needs a valid `name` and a string `value`' }, 400)
    }
    if (RESERVED_SECRET_NAMES.has(entry.name)) {
      return c.json({ message: `${entry.name} is reserved by the runtime` }, 400)
    }
    secrets.push({ name: entry.name, value: entry.value })
  }
  await upsertFunctionSecrets(ref, secrets)
  await syncSecretsFile(ref, resolved.dir)
  return c.json({}, 201)
})

app.delete('/platform/projects/:ref/secrets', async (c) => {
  const ref = c.req.param('ref')
  const resolved = await resolveFunctionsDir(ref)
  if ('status' in resolved) return c.json({ message: resolved.message }, resolved.status)
  const payload = await c.req.json<string[]>()
  if (!Array.isArray(payload) || payload.some((name) => typeof name !== 'string')) {
    return c.json({ message: 'body must be an array of secret names' }, 400)
  }
  await deleteFunctionSecrets(ref, payload)
  await syncSecretsFile(ref, resolved.dir)
  return c.json({})
})

// -- Third-party auth ----------------------------------------------------

function thirdPartyResponse(integration: ThirdPartyIntegration) {
  return {
    id: integration.id,
    type: integration.type,
    oidc_issuer_url: integration.oidc_issuer_url,
    jwks_url: integration.jwks_url,
    custom_jwks: integration.custom_jwks,
    resolved_jwks: integration.resolved_jwks,
    resolved_at: integration.resolved_at
      ? new Date(integration.resolved_at).toISOString()
      : null,
    inserted_at: new Date(integration.inserted_at).toISOString(),
    updated_at: new Date(integration.updated_at).toISOString(),
  }
}

app.get('/platform/projects/:ref/config/auth/third-party-auth', async (c) => {
  const ref = await resolveAuthRef(c.req.param('ref'))
  if (!ref) return c.json({ message: 'Auth is not available for this project' }, 404)
  return c.json((await listIntegrations(ref)).map(thirdPartyResponse))
})

app.post('/platform/projects/:ref/config/auth/third-party-auth', async (c) => {
  const ref = await resolveAuthRef(c.req.param('ref'))
  if (!ref) return c.json({ message: 'Auth is not available for this project' }, 404)
  const payload = await c.req.json<{
    oidc_issuer_url?: string | null
    jwks_url?: string | null
    custom_jwks?: unknown
  }>()
  try {
    const integration = await createIntegration(ref, payload)
    return c.json(thirdPartyResponse(integration), 201)
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return c.json({ message }, 400)
  }
})

app.get('/platform/projects/:ref/config/auth/third-party-auth/:id', async (c) => {
  const ref = await resolveAuthRef(c.req.param('ref'))
  if (!ref) return c.json({ message: 'Auth is not available for this project' }, 404)
  const integration = await getIntegration(ref, c.req.param('id'))
  if (!integration) return c.json({ message: 'integration not found' }, 404)
  return c.json(thirdPartyResponse(integration))
})

app.delete('/platform/projects/:ref/config/auth/third-party-auth/:id', async (c) => {
  const ref = await resolveAuthRef(c.req.param('ref'))
  if (!ref) return c.json({ message: 'Auth is not available for this project' }, 404)
  const integration = await deleteIntegration(ref, c.req.param('id'))
  if (!integration) return c.json({ message: 'integration not found' }, 404)
  return c.json(thirdPartyResponse(integration))
})

// -- Dashboard authentication ---------------------------------------------
//
// Validates dashboard sessions for the gateway. The login UI itself is
// Studio's /sign-in page, which posts credentials here as JSON.

app.get('/dashboard-auth/check', async (c) => {
  const cookie = c.req.header('cookie') ?? ''
  const token = getCookie(cookie, SESSION_COOKIE)
  if (token && isValidSessionToken(token)) {
    const session = getSessionIdentity(token)
    // Sessions only stay valid while their user still exists, so removed
    // members lose dashboard access on their next request.
    if (session !== null) {
      if (env.dashboardUsername && session.username === env.dashboardUsername) {
        return c.body(null, 200)
      }
      if ((await getDashboardUser(session.username)) !== null) {
        return c.body(null, 200)
      }
    }
    c.header('Set-Cookie', sessionCookie(null))
    return c.body(null, 401)
  }
  // Keep Basic Auth working for programmatic access (e.g. curl, older tools).
  const authorization = c.req.header('authorization') ?? ''
  if (authorization && isValidBasicAuthHeader(authorization)) return c.body(null, 200)
  return c.body(null, 401)
})

app.get('/dashboard-auth/login', (c) => {
  // Legacy entrypoint: the login UI now lives on Studio's own sign-in page.
  const redirectTo = sanitizeRedirectPath(c.req.query('redirect_to'))
  return c.redirect(`/sign-in?returnTo=${encodeURIComponent(redirectTo)}`, 302)
})

app.post('/dashboard-auth/login', async (c) => {
  // x-envoy-external-address is set by the gateway itself; the last entry of
  // X-Forwarded-For is the one it appended. Earlier entries are client
  // supplied and would let an attacker rotate the rate limit key.
  const forwardedFor = c.req.header('x-forwarded-for')?.split(',') ?? []
  const clientKey =
    c.req.header('x-envoy-external-address') ||
    forwardedFor.at(-1)?.trim() ||
    'unknown'
  if (isLoginRateLimited(clientKey)) {
    return c.json({ message: 'Too many sign in attempts, try again later' }, 429)
  }

  const payload = await c.req.json<{ username?: string; password?: string }>().catch(() => null)
  const username = payload?.username ?? ''
  const password = payload?.password ?? ''

  // Env credentials remain the break-glass owner login; additional users
  // live in the database (managed via /platform/dashboard-users).
  let identity: DashboardSessionIdentity | null = null
  if (isValidCredentials(username, password)) {
    identity = { username, role: 'owner' }
  } else if (username && password) {
    const user = await verifyDashboardUser(username, password)
    if (user) identity = { username: user.username, role: user.role }
  }
  if (identity === null) {
    return c.json({ message: 'Invalid username or password' }, 401)
  }

  resetLoginRateLimit(clientKey)
  // Accounts with a verified TOTP factor get a short-lived pending token
  // instead of a session; the session is only issued after a correct code.
  if (await hasVerifiedFactor(identity.username)) {
    return c.json({ mfa_required: true, mfa_token: createMfaPendingToken(identity) })
  }
  c.header('Set-Cookie', sessionCookie(createSessionToken(identity)))
  return c.json({ message: 'ok' })
})

// Second login step for accounts with TOTP enabled.
app.post('/dashboard-auth/mfa-verify', async (c) => {
  const forwardedFor = c.req.header('x-forwarded-for')?.split(',') ?? []
  const clientKey =
    c.req.header('x-envoy-external-address') || forwardedFor.at(-1)?.trim() || 'unknown'
  if (isLoginRateLimited(clientKey)) {
    return c.json({ message: 'Too many attempts, try again later' }, 429)
  }

  const payload = await c.req.json<{ mfa_token?: string; code?: string }>().catch(() => null)
  const identity = getMfaPendingIdentity(payload?.mfa_token ?? '')
  if (identity === null) {
    return c.json({ message: 'sign in again to continue' }, 401)
  }
  const code = typeof payload?.code === 'string' ? payload.code.trim() : ''
  const secrets = await listVerifiedFactorSecrets(identity.username)
  if (!secrets.some((secret) => verifyTotpCode(secret, code))) {
    return c.json({ message: 'Invalid verification code' }, 401)
  }

  resetLoginRateLimit(clientKey)
  c.header('Set-Cookie', sessionCookie(createSessionToken(identity)))
  return c.json({ message: 'ok' })
})

// Accepts a one-time invitation and creates the dashboard account. Only
// needs the invitation token, so it lives next to login (no session yet).
app.post('/dashboard-auth/accept-invitation', async (c) => {
  const forwardedFor = c.req.header('x-forwarded-for')?.split(',') ?? []
  const clientKey =
    c.req.header('x-envoy-external-address') || forwardedFor.at(-1)?.trim() || 'unknown'
  if (isLoginRateLimited(clientKey)) {
    return c.json({ message: 'Too many attempts, try again later' }, 429)
  }

  const payload = await c
    .req
    .json<{ token?: string; username?: string; password?: string }>()
    .catch(() => null)
  if (!payload?.token || typeof payload.token !== 'string') {
    return c.json({ message: 'body must contain an invitation `token`' }, 400)
  }
  if (
    !payload.username ||
    typeof payload.username !== 'string' ||
    !/^[A-Za-z0-9_.@-]{3,64}$/.test(payload.username)
  ) {
    return c.json({ message: 'username must be 3-64 chars (letters, digits, _.@-)' }, 400)
  }
  if (!payload.password || typeof payload.password !== 'string' || payload.password.length < 8) {
    return c.json({ message: 'password must be at least 8 characters' }, 400)
  }

  const result = await acceptInvitation({
    token: payload.token,
    username: payload.username,
    password: payload.password,
  })
  if (result === 'invalid_token') {
    return c.json({ message: 'invitation is invalid, expired or already used' }, 400)
  }
  if (result === 'username_taken') {
    return c.json({ message: 'username already exists' }, 409)
  }
  resetLoginRateLimit(clientKey)
  c.header('Set-Cookie', sessionCookie(createSessionToken({ username: result.username, role: result.role })))
  const [organization] = await listOrganizations()
  return c.json(
    {
      username: result.username,
      role: result.role,
      organization_slug: organization?.slug ?? null,
    },
    201
  )
})

app.post('/dashboard-auth/logout', (c) => {
  c.header('Set-Cookie', sessionCookie(null))
  return c.json({ message: 'ok' })
})

// -- Projects & organizations ---------------------------------------------

function projectResponse(project: ProjectRecord) {
  return {
    id: project.id,
    ref: project.ref,
    name: project.name,
    organization_id: project.organization_id,
    kind: 'default',
    status: project.status,
    status_detail: project.status_detail,
    cloud_provider: 'localhost',
    region: 'local',
    inserted_at: new Date(project.inserted_at).toISOString(),
    endpoint: null,
    database: null,
  }
}

app.get('/platform/organizations', async (c) => {
  return c.json(await listOrganizations())
})

app.patch('/platform/organizations/:slug', async (c) => {
  if (!(await canAdminister(c))) {
    return c.json({ message: 'only owners and admins can update organizations' }, 403)
  }
  const payload = await c.req.json<{ name?: string; opt_in_tags?: string[] }>().catch(() => null)
  if (!payload) return c.json({ message: 'invalid JSON body' }, 400)
  const patch: { name?: string; opt_in_tags?: string[] } = {}
  if (payload.name !== undefined) {
    if (typeof payload.name !== 'string' || payload.name.trim().length === 0) {
      return c.json({ message: '`name` must be a non-empty string' }, 400)
    }
    patch.name = payload.name.trim()
  }
  if (payload.opt_in_tags !== undefined) {
    if (
      !Array.isArray(payload.opt_in_tags) ||
      payload.opt_in_tags.some((tag) => typeof tag !== 'string')
    ) {
      return c.json({ message: '`opt_in_tags` must be an array of strings' }, 400)
    }
    patch.opt_in_tags = payload.opt_in_tags
  }
  const updated = await updateOrganization(c.req.param('slug'), patch)
  if (!updated) return c.json({ message: 'organization not found' }, 404)
  return c.json(updated)
})

app.post('/platform/organizations', async (c) => {
  const payload = await c.req.json<{ name?: string }>().catch(() => null)
  if (!payload?.name || typeof payload.name !== 'string') {
    return c.json({ message: 'body must contain a `name` string' }, 400)
  }
  return c.json(await createOrganization(payload.name), 201)
})

app.get('/platform/projects', async (c) => {
  return c.json((await listProjects()).map(projectResponse))
})

app.post('/platform/projects', async (c) => {
  return c.json(
    { message: 'self-hosted Supabase runs a single project; creating projects is not supported' },
    501
  )
})

app.get('/platform/projects/:ref', async (c) => {
  const project = await getProject(c.req.param('ref'))
  if (!project) return c.json({ message: 'project not found' }, 404)
  return c.json(projectResponse(project))
})

app.get('/platform/projects/:ref/api-keys', async (c) => {
  const project = await getProject(c.req.param('ref'))
  if (!project) return c.json({ message: 'project not found' }, 404)
  return c.json([])
})

app.delete('/platform/projects/:ref', async (c) => {
  if (!(await canAdminister(c))) {
    return c.json({ message: 'only owners and admins can delete projects' }, 403)
  }
  const project = await getProject(c.req.param('ref'))
  if (!project) return c.json({ message: 'project not found' }, 404)
  return c.json({ message: 'the default project cannot be deleted' }, 400)
})

// -- Storage configuration --------------------------------------------------

app.get('/platform/projects/:ref/config/storage', async (c) => {
  const config = await getStorageConfig(c.req.param('ref'))
  if (config === null) {
    return c.json({ message: 'Storage is not available for this project' }, 404)
  }
  return c.json(config)
})

app.get('/platform/storage/:ref/s3-protocol', async (c) => {
  if (!(await canAdminister(c))) {
    return c.json({ message: 'only owners and admins can view S3 credentials' }, 403)
  }
  const info = await getS3ProtocolInfo(c.req.param('ref'))
  if (info === null) {
    return c.json({ message: 'Storage is not available for this project' }, 404)
  }
  return c.json(info)
})

// -- Realtime configuration -------------------------------------------------

app.get('/platform/projects/:ref/config/realtime', async (c) => {
  const config = await getRealtimeConfig(c.req.param('ref'))
  if (config === null) {
    return c.json({ message: 'Realtime is not available for this project' }, 404)
  }
  return c.json(config)
})

app.patch('/platform/projects/:ref/config/realtime', async (c) => {
  if (!(await canAdminister(c))) {
    return c.json({ message: 'only owners and admins can update realtime settings' }, 403)
  }
  const body = (await c.req.json().catch(() => null)) as Record<string, unknown> | null
  if (body === null) return c.json({ message: 'invalid JSON body' }, 400)
  const config = await updateRealtimeConfig(c.req.param('ref'), body)
  if (config === null) {
    return c.json({ message: 'Realtime is not available for this project' }, 404)
  }
  return c.json(config)
})

// -- Dashboard users (teams) ----------------------------------------------

app.get('/platform/dashboard-users', async (c) => {
  const users = await listDashboardUsers()
  const mfaUsernames = await listUsernamesWithVerifiedFactors()
  const withMfa = users.map((user) => ({
    ...user,
    mfa_enabled: mfaUsernames.has(user.username),
  }))
  // The break-glass `.env` login is not a dashboard_users row; surface it as a
  // virtual owner so member lists are complete for every viewer.
  if (env.dashboardUsername && !withMfa.some((u) => u.username === env.dashboardUsername)) {
    return c.json([
      {
        id: 0,
        username: env.dashboardUsername,
        role: 'owner',
        first_name: '',
        last_name: '',
        mfa_enabled: false,
        inserted_at: '',
      },
      ...withMfa,
    ])
  }
  return c.json(withMfa)
})

// The caller's own identity/role, for role-aware UI.
app.get('/platform/profile', async (c) => {
  const identity = await requestIdentity(c)
  if (identity === 'invalid') {
    c.header('Set-Cookie', sessionCookie(null))
    return c.json({ message: 'session is no longer valid' }, 401)
  }
  if (!identity) return c.json({ username: 'service', role: 'owner' })
  const profile = await getDashboardProfile(identity.username)
  return c.json({
    ...identity,
    first_name: profile.first_name,
    last_name: profile.last_name,
  })
})

// Audit trail of mutating management API requests, for the account page.
app.get('/platform/profile/audit', async (c) => {
  const identity = await requestIdentity(c)
  if (identity === 'invalid') {
    c.header('Set-Cookie', sessionCookie(null))
    return c.json({ message: 'session is no longer valid' }, 401)
  }
  const start = new Date(c.req.query('iso_timestamp_start') ?? '')
  const end = new Date(c.req.query('iso_timestamp_end') ?? '')
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
    return c.json({ message: 'iso_timestamp_start and iso_timestamp_end are required' }, 400)
  }
  const logs = await listAuditLogs({ start, end })
  return c.json({ result: logs, retention_period: 0 })
})

// Lets the signed-in dashboard user update their own profile details.
app.patch('/platform/profile', async (c) => {
  const identity = await requestIdentity(c)
  if (identity === 'invalid') {
    c.header('Set-Cookie', sessionCookie(null))
    return c.json({ message: 'session is no longer valid' }, 401)
  }
  if (!identity) return c.json({ message: 'sign in to update your profile' }, 401)
  const payload = await c
    .req
    .json<{ first_name?: string; last_name?: string }>()
    .catch(() => null)
  if (payload === null) return c.json({ message: 'invalid payload' }, 400)
  const firstName = typeof payload.first_name === 'string' ? payload.first_name.trim() : ''
  const lastName = typeof payload.last_name === 'string' ? payload.last_name.trim() : ''
  await updateDashboardUserProfile(identity.username, { firstName, lastName })
  return c.json({
    ...identity,
    first_name: firstName,
    last_name: lastName,
  })
})

// Lets the signed-in dashboard user rotate their own password.
app.post('/platform/profile/password', async (c) => {
  const identity = await requestIdentity(c)
  if (identity === 'invalid') {
    c.header('Set-Cookie', sessionCookie(null))
    return c.json({ message: 'session is no longer valid' }, 401)
  }
  if (!identity) {
    return c.json({ message: 'sign in to change your password' }, 401)
  }
  const payload = await c
    .req
    .json<{ current_password?: string; new_password?: string }>()
    .catch(() => null)
  const currentPassword = payload?.current_password
  const newPassword = payload?.new_password
  if (typeof currentPassword !== 'string' || currentPassword.length === 0) {
    return c.json({ message: 'current password is required' }, 400)
  }
  if (typeof newPassword !== 'string' || newPassword.length < 8) {
    return c.json({ message: 'new password must be at least 8 characters' }, 400)
  }
  const result = await updateDashboardUserPassword(identity.username, currentPassword, newPassword)
  if (result === 'not_found') {
    // The break-glass .env login has no database row; its password lives in .env.
    return c.json({ message: 'this account is managed via environment variables' }, 400)
  }
  if (result === 'wrong_password') {
    return c.json({ message: 'current password is incorrect' }, 400)
  }
  return c.json({})
})

// -- Dashboard MFA (TOTP factors of the signed-in user) --------------------

/** Cookie-authenticated user for the profile MFA endpoints. */
async function factorOwner(c: {
  req: { header: (name: string) => string | undefined }
}): Promise<DashboardSessionIdentity | null> {
  const identity = await requestIdentity(c)
  if (identity === 'invalid' || identity === null) return null
  return identity
}

app.get('/platform/profile/factors', async (c) => {
  const identity = await factorOwner(c)
  if (!identity) return c.json({ message: 'sign in to manage MFA factors' }, 401)
  const factors = await listUserFactors(identity.username)
  return c.json(
    factors.map((f) => ({
      id: f.id,
      friendly_name: f.friendly_name,
      status: f.status,
      inserted_at: new Date(f.inserted_at).toISOString(),
    }))
  )
})

app.post('/platform/profile/factors', async (c) => {
  const identity = await factorOwner(c)
  if (!identity) return c.json({ message: 'sign in to manage MFA factors' }, 401)
  const payload = await c.req.json<{ friendly_name?: string }>().catch(() => null)
  const friendlyName =
    typeof payload?.friendly_name === 'string' ? payload.friendly_name.slice(0, 64) : ''
  const secret = generateTotpSecret()
  const factor = await createUserFactor({
    username: identity.username,
    friendlyName,
    secret,
  })
  // The secret is only returned once, at enrollment.
  return c.json(
    {
      id: factor.id,
      friendly_name: factor.friendly_name,
      status: factor.status,
      totp: { secret, uri: totpUri(secret, identity.username, 'Supabase Studio') },
    },
    201
  )
})

app.post('/platform/profile/factors/:id/verify', async (c) => {
  const identity = await factorOwner(c)
  if (!identity) return c.json({ message: 'sign in to manage MFA factors' }, 401)
  const factorId = Number(c.req.param('id'))
  if (!Number.isInteger(factorId)) return c.json({ message: 'invalid factor id' }, 400)
  const payload = await c.req.json<{ code?: string }>().catch(() => null)
  const code = typeof payload?.code === 'string' ? payload.code.trim() : ''
  const factor = await getUserFactorSecret(identity.username, factorId)
  if (!factor) return c.json({ message: 'factor not found' }, 404)
  if (!verifyTotpCode(factor.secret, code)) {
    return c.json({ message: 'invalid verification code' }, 400)
  }
  await markFactorVerified(identity.username, factorId)
  return c.json({ id: factorId, status: 'verified' })
})

app.delete('/platform/profile/factors/:id', async (c) => {
  const identity = await factorOwner(c)
  if (!identity) return c.json({ message: 'sign in to manage MFA factors' }, 401)
  const factorId = Number(c.req.param('id'))
  if (!Number.isInteger(factorId)) return c.json({ message: 'invalid factor id' }, 400)
  const deleted = await deleteUserFactor(identity.username, factorId)
  if (!deleted) return c.json({ message: 'factor not found' }, 404)
  return c.json({})
})

app.post('/platform/dashboard-users', async (c) => {
  if (!(await canAdminister(c))) {
    return c.json({ message: 'only owners and admins can manage users' }, 403)
  }
  const payload = await c
    .req
    .json<{ username?: string; password?: string; role?: string }>()
    .catch(() => null)
  if (
    !payload?.username ||
    typeof payload.username !== 'string' ||
    !/^[A-Za-z0-9_.@-]{3,64}$/.test(payload.username)
  ) {
    return c.json({ message: 'username must be 3-64 chars (letters, digits, _.@-)' }, 400)
  }
  if (!payload.password || typeof payload.password !== 'string' || payload.password.length < 8) {
    return c.json({ message: 'password must be at least 8 characters' }, 400)
  }
  const role = payload.role ?? 'developer'
  if (!DASHBOARD_ROLES.has(role)) {
    return c.json({ message: 'role must be owner, admin or developer' }, 400)
  }
  if (role === 'owner' && !(await isOwner(c))) {
    return c.json({ message: 'only owners can grant the owner role' }, 403)
  }
  try {
    const user = await createDashboardUser({
      username: payload.username,
      password: payload.password,
      role: role as DashboardRole,
    })
    return c.json(user, 201)
  } catch {
    return c.json({ message: 'username already exists' }, 409)
  }
})

app.patch('/platform/dashboard-users/:username', async (c) => {
  if (!(await canAdminister(c))) {
    return c.json({ message: 'only owners and admins can manage users' }, 403)
  }
  const payload = await c.req.json<{ role?: string }>().catch(() => null)
  const role = payload?.role
  if (!role || !DASHBOARD_ROLES.has(role)) {
    return c.json({ message: 'role must be owner, admin or developer' }, 400)
  }
  const username = c.req.param('username')
  const users = await listDashboardUsers()
  const target = users.find((u) => u.username === username)
  if ((role === 'owner' || target?.role === 'owner') && !(await isOwner(c))) {
    return c.json({ message: 'only owners can manage the owner role' }, 403)
  }
  const result = await updateDashboardUserRole(username, role as DashboardRole)
  if (result.lastOwner) {
    return c.json({ message: 'the last owner cannot be demoted' }, 400)
  }
  if (!result.updated) return c.json({ message: 'user not found' }, 404)
  return c.json({})
})

app.delete('/platform/dashboard-users/:username', async (c) => {
  const username = c.req.param('username')
  const identity = await requestIdentity(c)
  if (identity === 'invalid') {
    return c.json({ message: 'session is no longer valid' }, 401)
  }
  const isSelfRemoval = identity !== null && identity.username === username
  if (!isSelfRemoval && !(await canAdminister(c))) {
    return c.json({ message: 'only owners and admins can manage users' }, 403)
  }
  const existing = (await listDashboardUsers()).find((u) => u.username === username)
  if (existing?.role === 'owner' && !(await isOwner(c))) {
    return c.json({ message: 'only owners can remove owners' }, 403)
  }
  const result = await deleteDashboardUser(username)
  if (result.lastOwner) {
    return c.json({ message: 'the last owner cannot be deleted' }, 400)
  }
  if (!result.deleted) return c.json({ message: 'user not found' }, 404)
  // Leaving the team also ends the leaver's session right away.
  if (isSelfRemoval) c.header('Set-Cookie', sessionCookie(null))
  return c.json({})
})

app.get('/platform/dashboard-users/invitations', async (c) => {
  return c.json(await listInvitations())
})

// Whether invitation emails can be delivered (SMTP host + sender configured).
app.get('/platform/dashboard-users/smtp-status', async (c) => {
  return c.json({ configured: await isSmtpConfigured() })
})

app.post('/platform/dashboard-users/invitations', async (c) => {
  if (!(await canAdminister(c))) {
    return c.json({ message: 'only owners and admins can invite users' }, 403)
  }
  const payload = await c
    .req
    .json<{ role?: string; invited_email?: string }>()
    .catch(() => null)
  const role = payload?.role ?? 'developer'
  if (!DASHBOARD_ROLES.has(role)) {
    return c.json({ message: 'role must be owner, admin or developer' }, 400)
  }
  if (role === 'owner' && !(await isOwner(c))) {
    return c.json({ message: 'only owners can invite new owners' }, 403)
  }
  const invitedEmail = typeof payload?.invited_email === 'string' ? payload.invited_email : ''
  if (invitedEmail.length > 320) {
    return c.json({ message: 'invited_email is too long' }, 400)
  }
  const identity = await requestIdentity(c)
  const invitedBy = identity !== null && identity !== 'invalid' ? identity.username : 'service'
  const { invitation, token } = await createInvitation({
    role: role as DashboardRole,
    invitedBy,
    invitedEmail,
  })

  // Deliver via the deployment's SMTP (the same settings GoTrue uses).
  // Delivery problems never fail the invitation itself: the raw token is
  // still returned so the link can be shared manually.
  let emailSent = false
  let emailError: string | null = null
  if (invitedEmail) {
    const joinUrl = `${env.publicUrl.replace(/\/$/, '')}/join?token=${token}`
    try {
      emailSent = await sendInvitationEmail({
        to: invitedEmail,
        joinUrl,
        invitedBy,
        role,
      })
      if (!emailSent) emailError = 'SMTP is not configured'
    } catch (err) {
      emailError = err instanceof Error ? err.message : 'failed to send the invitation email'
    }
  }

  // The raw token is only returned here, once; the DB stores its hash.
  return c.json({ ...invitation, token, email_sent: emailSent, email_error: emailError }, 201)
})

app.delete('/platform/dashboard-users/invitations/:id', async (c) => {
  if (!(await canAdminister(c))) {
    return c.json({ message: 'only owners and admins can manage invitations' }, 403)
  }
  const id = Number(c.req.param('id'))
  if (!Number.isInteger(id)) return c.json({ message: 'invalid invitation id' }, 400)
  const deleted = await deleteInvitation(id)
  if (!deleted) return c.json({ message: 'invitation not found' }, 404)
  return c.json({})
})

// -- PostgREST configuration --------------------------------------------

app.get('/platform/projects/:ref/config/postgrest', async (c) => {
  const config = await getPostgrestConfig(c.req.param('ref'))
  if (!config) return c.json({ message: 'PostgREST is not available for this project' }, 404)
  return c.json(config)
})

app.patch('/platform/projects/:ref/config/postgrest', async (c) => {
  const payload = await c.req.json<{
    db_schema?: string
    max_rows?: number
    db_extra_search_path?: string
    db_pool?: number | null
  }>()
  const patch: Parameters<typeof updatePostgrestConfig>[1] = {}
  if (payload.db_schema !== undefined) {
    if (typeof payload.db_schema !== 'string') {
      return c.json({ message: 'db_schema must be a string' }, 400)
    }
    patch.db_schema = payload.db_schema
  }
  if (payload.max_rows !== undefined) {
    if (typeof payload.max_rows !== 'number' || !Number.isFinite(payload.max_rows)) {
      return c.json({ message: 'max_rows must be a number' }, 400)
    }
    patch.max_rows = payload.max_rows
  }
  if (payload.db_extra_search_path !== undefined) {
    if (typeof payload.db_extra_search_path !== 'string') {
      return c.json({ message: 'db_extra_search_path must be a string' }, 400)
    }
    patch.db_extra_search_path = payload.db_extra_search_path
  }
  if (payload.db_pool !== undefined) {
    if (payload.db_pool !== null && typeof payload.db_pool !== 'number') {
      return c.json({ message: 'db_pool must be a number or null' }, 400)
    }
    patch.db_pool = payload.db_pool
  }
  const updated = await updatePostgrestConfig(c.req.param('ref'), patch)
  if (!updated) return c.json({ message: 'PostgREST is not available for this project' }, 404)
  return c.json(updated)
})

// -- Postgres configuration ---------------------------------------------

app.get('/platform/projects/:ref/config/database/postgres', async (c) => {
  const config = await getPostgresConfig(c.req.param('ref'))
  if (!config) return c.json({ message: 'Postgres config is not available for this project' }, 404)
  return c.json(config)
})

app.put('/platform/projects/:ref/config/database/postgres', async (c) => {
  const payload = await c.req.json<Record<string, unknown>>()
  const patch: Record<string, PostgresConfigValue> = {}
  for (const [name, value] of Object.entries(payload)) {
    if (name === 'restart_database') continue
    if (!isManagedGuc(name)) return c.json({ message: `unsupported setting: ${name}` }, 400)
    const error = validateGucValue(name, value)
    if (error) return c.json({ message: error }, 400)
    patch[name] = value as PostgresConfigValue
  }

  try {
    const result = await updatePostgresConfig(c.req.param('ref'), patch)
    if (!result) {
      return c.json({ message: 'Postgres config is not available for this project' }, 404)
    }
    return c.json(result.config)
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return c.json({ message }, 400)
  }
})

async function main() {
  await migrate()
  await migrateThirdPartyAuth()
  await migrateProjects()
  await migrateDashboardUsers()
  await migrateAuditLogs()
  await syncEnvFile()
  // PostgREST reads its trusted key set from a file this service owns, so it
  // has to exist (with the stack's own keys) before PostgREST starts.
  await syncThirdPartyJwks()
  if (env.functionsDir) await syncFunctionManifest('default', env.functionsDir)
  serve({ fetch: app.fetch, port: env.port }, (info) => {
    console.log(`management-api listening on :${info.port}`)
  })
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
