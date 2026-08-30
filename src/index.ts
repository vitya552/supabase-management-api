import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { logger } from 'hono/logger'
import { createHash, timingSafeEqual } from 'node:crypto'
import pg from 'pg'

import { AUTH_CONFIG_KEYS } from './auth-config-keys.js'
import { baselineConfig } from './baseline.js'
import {
  createSessionToken,
  type DashboardSessionIdentity,
  getCookie,
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
  DASHBOARD_ROLES,
  type DashboardRole,
  deleteDashboardUser,
  deleteInvitation,
  listDashboardUsers,
  listInvitations,
  migrateDashboardUsers,
  updateDashboardUserRole,
  verifyDashboardUser,
} from './dashboard-users.js'
import { renderReactEmail } from './emails.js'
import { defaultAuthConfig } from './gotrue-defaults.js'
import { env } from './env.js'
import { syncEnvFile, templateTypeFromConfigKey } from './envfile.js'
import {
  deleteFunctionFiles,
  type FunctionFile,
  isValidSlug,
  writeFunctionFiles,
  writeManifestFile,
  writeSecretsFile,
} from './functions.js'
import { proxyProjectRequest } from './project-proxy.js'
import {
  createOrganization,
  createProjectRecord,
  generateRef,
  getProject,
  listOrganizations,
  listProjects,
  migrateProjects,
  type ProjectRecord,
} from './projects-store.js'
import {
  deprovisionProject,
  projectsConfigured,
  provisionProject,
  resumeProjects,
} from './provisioner.js'
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
  const template = await getEmailTemplate(c.req.param('type'))
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

/**
 * Dashboard identity of the request, taken from the forwarded session cookie
 * (Studio forwards it on proxied calls). Requests without a session cookie
 * are direct token-authenticated API calls and act with full (owner) rights.
 */
function requestIdentity(c: {
  req: { header: (name: string) => string | undefined }
}): DashboardSessionIdentity | null {
  const token = getCookie(c.req.header('cookie') ?? '', SESSION_COOKIE)
  if (!token) return null
  return getSessionIdentity(token)
}

/** True when the request may perform owner/admin-only actions. */
function canAdminister(c: {
  req: { header: (name: string) => string | undefined }
}): boolean {
  const identity = requestIdentity(c)
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

async function applyConfigPatch(payload: Record<string, unknown>) {
  const { valid, errors } = validateConfigPayload(payload)
  if (errors.length > 0) return { errors }

  // Template content updates also materialize a rendered template that
  // GoTrue fetches over HTTP.
  for (const [key, value] of Object.entries(valid)) {
    const templateType = templateTypeFromConfigKey(key)
    if (!templateType) continue
    if (value === null) {
      await deleteEmailTemplate(templateType)
    } else if (typeof value === 'string') {
      await upsertEmailTemplate({
        template_type: templateType,
        source: value,
        source_format: 'html',
        rendered_html: value,
      })
    }
  }

  await upsertConfig(valid)
  await syncEnvFile()
  return { errors: [] as string[] }
}

async function currentConfig() {
  return { ...defaultAuthConfig(), ...baselineConfig(), ...(await getAllConfig()) }
}

app.get('/platform/auth/:ref/config', async (c) => {
  return c.json(await currentConfig())
})

app.patch('/platform/auth/:ref/config', async (c) => {
  const payload = await c.req.json<Record<string, unknown>>()
  const { errors } = await applyConfigPatch(payload)
  if (errors.length > 0) return c.json({ message: errors.join('; ') }, 400)
  return c.json(await currentConfig())
})

app.patch('/platform/auth/:ref/config/hooks', async (c) => {
  const payload = await c.req.json<Record<string, unknown>>()
  const { errors } = await applyConfigPatch(payload)
  if (errors.length > 0) return c.json({ message: errors.join('; ') }, 400)
  return c.json(await currentConfig())
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
  const template = templateParam(c)
  if (!template) return c.json({ message: 'unknown template type' }, 400)
  await deleteEmailTemplate(template)
  await deleteConfig([
    `MAILER_TEMPLATES_${template.toUpperCase()}_CONTENT`,
    `MAILER_SUBJECTS_${template.toUpperCase()}`,
  ])
  await syncEnvFile()
  return c.json(await currentConfig())
})

/**
 * React email templates (self-hosted extension endpoint). Accepts TSX
 * source with a react-email component as its default export, renders it to
 * HTML and wires it up as the GoTrue template for the given type.
 */
app.put('/platform/auth/:ref/templates/:template/react', async (c) => {
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

  await upsertEmailTemplate({
    template_type: template,
    source,
    source_format: 'react',
    rendered_html: renderedHtml,
  })
  await upsertConfig({ [`MAILER_TEMPLATES_${template.toUpperCase()}_CONTENT`]: renderedHtml })
  await syncEnvFile()
  return c.json({ template_type: template, rendered_html: renderedHtml })
})

app.get('/platform/auth/:ref/templates/:template/react', async (c) => {
  const type = templateParam(c)
  if (!type) return c.json({ message: 'unknown template type' }, 400)
  const template = await getEmailTemplate(type)
  if (!template || template.source_format !== 'react') {
    return c.json({ message: 'react template not found' }, 404)
  }
  return c.json(template)
})

// -- Edge Functions -----------------------------------------------------

const MAX_FUNCTION_FILES = 100
const MAX_FUNCTION_BYTES = 10 * 1024 * 1024

/** Republishes per-function settings the `main` dispatcher enforces. */
async function syncFunctionManifest() {
  await writeManifestFile(env.functionsDir, await getEdgeFunctions())
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

app.use('/platform/projects/:ref/functions/*', async (c, next) => {
  if (!env.functionsDir) {
    return c.json({ message: 'edge functions management is not configured (FUNCTIONS_DIR)' }, 501)
  }
  await next()
})

app.get('/platform/projects/:ref/functions', async (c) => {
  return c.json((await getEdgeFunctions()).map(functionResponse))
})

app.post('/platform/projects/:ref/functions/deploy', async (c) => {
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
    await writeFunctionFiles(env.functionsDir, slug, files)
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return c.json({ message }, 400)
  }

  const fn = await upsertEdgeFunction({
    slug,
    name: metadata.name ?? slug,
    verify_jwt: metadata.verify_jwt ?? true,
    entrypoint_path: metadata.entrypoint_path ?? null,
    import_map_path: metadata.import_map_path ?? null,
  })
  await syncFunctionManifest()
  return c.json(functionResponse(fn))
})

app.get('/platform/projects/:ref/functions/:slug', async (c) => {
  const fn = await getEdgeFunction(c.req.param('slug'))
  if (!fn) return c.json({ message: 'function not found' }, 404)
  return c.json(functionResponse(fn))
})

app.patch('/platform/projects/:ref/functions/:slug', async (c) => {
  const payload = await c.req.json<{ name?: string; verify_jwt?: boolean }>()
  const fn = await updateEdgeFunction(c.req.param('slug'), payload)
  if (!fn) return c.json({ message: 'function not found' }, 404)
  await syncFunctionManifest()
  return c.json(functionResponse(fn))
})

app.delete('/platform/projects/:ref/functions/:slug', async (c) => {
  const slug = c.req.param('slug')
  if (!isValidSlug(slug)) return c.json({ message: `invalid function slug: ${slug}` }, 400)
  await deleteFunctionFiles(env.functionsDir, slug)
  await deleteEdgeFunction(slug)
  await syncFunctionManifest()
  return c.json({ slug })
})

// -- Edge Function secrets ----------------------------------------------

async function syncSecretsFile() {
  const secrets = await getFunctionSecrets()
  const out: Record<string, string> = {}
  for (const secret of secrets) out[secret.name] = secret.value
  await writeSecretsFile(env.functionsDir, out)
}

app.use('/platform/projects/:ref/secrets', async (c, next) => {
  if (!env.functionsDir) {
    return c.json({ message: 'edge functions management is not configured (FUNCTIONS_DIR)' }, 501)
  }
  await next()
})

app.get('/platform/projects/:ref/secrets', async (c) => {
  const secrets = await getFunctionSecrets()
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
  await upsertFunctionSecrets(secrets)
  await syncSecretsFile()
  return c.json({}, 201)
})

app.delete('/platform/projects/:ref/secrets', async (c) => {
  const payload = await c.req.json<string[]>()
  if (!Array.isArray(payload) || payload.some((name) => typeof name !== 'string')) {
    return c.json({ message: 'body must be an array of secret names' }, 400)
  }
  await deleteFunctionSecrets(payload)
  await syncSecretsFile()
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
  return c.json((await listIntegrations()).map(thirdPartyResponse))
})

app.post('/platform/projects/:ref/config/auth/third-party-auth', async (c) => {
  const payload = await c.req.json<{
    oidc_issuer_url?: string | null
    jwks_url?: string | null
    custom_jwks?: unknown
  }>()
  try {
    const integration = await createIntegration(payload)
    return c.json(thirdPartyResponse(integration), 201)
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return c.json({ message }, 400)
  }
})

app.get('/platform/projects/:ref/config/auth/third-party-auth/:id', async (c) => {
  const integration = await getIntegration(c.req.param('id'))
  if (!integration) return c.json({ message: 'integration not found' }, 404)
  return c.json(thirdPartyResponse(integration))
})

app.delete('/platform/projects/:ref/config/auth/third-party-auth/:id', async (c) => {
  const integration = await deleteIntegration(c.req.param('id'))
  if (!integration) return c.json({ message: 'integration not found' }, 404)
  return c.json(thirdPartyResponse(integration))
})

// -- Dashboard authentication ---------------------------------------------
//
// Validates dashboard sessions for the gateway. The login UI itself is
// Studio's /sign-in page, which posts credentials here as JSON.

app.get('/dashboard-auth/check', (c) => {
  const cookie = c.req.header('cookie') ?? ''
  const token = getCookie(cookie, SESSION_COOKIE)
  if (token && isValidSessionToken(token)) return c.body(null, 200)
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
  return c.json({ username: result.username, role: result.role }, 201)
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
    kind: project.kind,
    status: project.status,
    status_detail: project.status_detail,
    cloud_provider: 'localhost',
    region: 'local',
    inserted_at: new Date(project.inserted_at).toISOString(),
    // Compose projects: services live in their own stack behind /proj/<ref>.
    // External projects: only the database is managed.
    endpoint:
      project.kind === 'compose'
        ? `${env.publicUrl.replace(/\/$/, '')}/proj/${project.ref}`
        : null,
    database:
      project.kind === 'compose' && project.secrets
        ? {
            host: `sbproj-${project.ref}-db`,
            port: 5432,
            user: 'postgres',
            name: 'postgres',
          }
        : project.kind === 'external' && project.external_db_url
          ? externalDatabaseMetadata(project.external_db_url)
          : null,
  }
}

/** Maps a connection failure to a safe, credential-free message. */
function classifyConnectionError(err: unknown): string {
  const code =
    err !== null && typeof err === 'object' && 'code' in err && typeof err.code === 'string'
      ? err.code
      : ''
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return 'host not found'
  if (code === 'ECONNREFUSED') return 'connection refused'
  if (code === 'ETIMEDOUT' || code === 'ECONNRESET') return 'connection timed out'
  if (code === '28P01' || code === '28000') return 'authentication failed'
  if (code === '3D000') return 'database does not exist'
  if (err instanceof Error && /timeout/i.test(err.message)) return 'connection timed out'
  return 'connection failed'
}

/** Non-secret connection metadata for an external database URL. */
function externalDatabaseMetadata(dbUrl: string) {
  try {
    const url = new URL(dbUrl)
    return {
      host: url.hostname,
      port: url.port ? Number(url.port) : 5432,
      user: url.username ? decodeURIComponent(url.username) : 'postgres',
      name: url.pathname.replace(/^\//, '') || 'postgres',
    }
  } catch {
    return null
  }
}

/** Full connection string for a project's database. Never included in
 * project list/detail responses; callers fetch it explicitly. */
function projectConnectionString(project: ProjectRecord): string | null {
  if (project.kind === 'compose' && project.secrets) {
    return `postgresql://postgres:${encodeURIComponent(project.secrets.postgres_password)}@sbproj-${project.ref}-db:5432/postgres`
  }
  if (project.kind === 'external' && project.external_db_url) {
    return project.external_db_url
  }
  return null
}

app.get('/platform/organizations', async (c) => {
  return c.json(await listOrganizations())
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
  if (!canAdminister(c)) {
    return c.json({ message: 'only owners and admins can create projects' }, 403)
  }
  const payload = await c
    .req
    .json<{
      name?: string
      organization_id?: number
      kind?: string
      db_connection_string?: string
    }>()
    .catch(() => null)
  if (!payload?.name || typeof payload.name !== 'string') {
    return c.json({ message: 'body must contain a `name` string' }, 400)
  }
  const organizationId =
    typeof payload.organization_id === 'number' ? payload.organization_id : 1
  const kind = payload.kind ?? 'compose'

  if (kind === 'external') {
    const dbUrl = payload.db_connection_string
    if (!dbUrl || typeof dbUrl !== 'string' || !/^postgres(ql)?:\/\//.test(dbUrl)) {
      return c.json(
        { message: 'external projects need a postgres:// `db_connection_string`' },
        400
      )
    }
    let parsedDbUrl: URL
    try {
      parsedDbUrl = new URL(dbUrl)
    } catch {
      return c.json({ message: 'invalid database connection string' }, 400)
    }
    if (!parsedDbUrl.hostname) {
      return c.json({ message: 'database connection string must include a host' }, 400)
    }
    const probe = new pg.Client({
      connectionString: dbUrl,
      connectionTimeoutMillis: 10_000,
    })
    try {
      await probe.connect()
      await probe.query('select 1')
    } catch (err) {
      // pg errors can echo parts of the connection string; return only a
      // stable classification of the failure.
      const message = classifyConnectionError(err)
      return c.json({ message: `could not connect to database: ${message}` }, 400)
    } finally {
      await probe.end().catch(() => {})
    }
    const record = await createProjectRecord({
      ref: generateRef(),
      name: payload.name,
      organizationId,
      kind: 'external',
      externalDbUrl: dbUrl,
      status: 'ACTIVE_HEALTHY',
    })
    return c.json(projectResponse(record), 201)
  }

  if (kind !== 'compose') return c.json({ message: `unknown project kind: ${kind}` }, 400)
  if (!projectsConfigured()) {
    return c.json(
      { message: 'project provisioning is not configured (PROJECTS_DIR / PROJECTS_HOST_DIR)' },
      501
    )
  }
  const record = await provisionProject({ name: payload.name, organizationId })
  return c.json(projectResponse(record), 201)
})

app.get('/platform/projects/:ref', async (c) => {
  const project = await getProject(c.req.param('ref'))
  if (!project) return c.json({ message: 'project not found' }, 404)
  return c.json(projectResponse(project))
})

app.get('/platform/projects/:ref/connection-string', async (c) => {
  const project = await getProject(c.req.param('ref'))
  if (!project) return c.json({ message: 'project not found' }, 404)
  const connectionString = projectConnectionString(project)
  if (connectionString === null) {
    return c.json({ message: 'project has no managed database' }, 404)
  }
  return c.json({ connection_string: connectionString })
})

app.get('/platform/projects/:ref/api-keys', async (c) => {
  const project = await getProject(c.req.param('ref'))
  if (!project) return c.json({ message: 'project not found' }, 404)
  if (!project.secrets) return c.json([])
  return c.json([
    { name: 'anon key', api_key: project.secrets.anon_key, tags: 'anon' },
    { name: 'service_role key', api_key: project.secrets.service_role_key, tags: 'service_role' },
  ])
})

app.delete('/platform/projects/:ref', async (c) => {
  if (!canAdminister(c)) {
    return c.json({ message: 'only owners and admins can delete projects' }, 403)
  }
  const ref = c.req.param('ref')
  const project = await getProject(ref)
  if (!project) return c.json({ message: 'project not found' }, 404)
  if (project.kind === 'default') {
    return c.json({ message: 'the default project cannot be deleted' }, 400)
  }
  await deprovisionProject(ref)
  return c.json({ ref })
})

// Per-project API traffic (rest/auth/storage/functions), routed here by the
// gateway. The project's own services authenticate each request.
app.all('/proj/:ref/*', proxyProjectRequest)

// -- Dashboard users (teams) ----------------------------------------------

app.get('/platform/dashboard-users', async (c) => {
  return c.json(await listDashboardUsers())
})

// The caller's own identity/role, for role-aware UI.
app.get('/platform/profile', (c) => {
  const identity = requestIdentity(c)
  return c.json(identity ?? { username: 'service', role: 'owner' })
})

app.post('/platform/dashboard-users', async (c) => {
  if (!canAdminister(c)) {
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
  if (!canAdminister(c)) {
    return c.json({ message: 'only owners and admins can manage users' }, 403)
  }
  const payload = await c.req.json<{ role?: string }>().catch(() => null)
  const role = payload?.role
  if (!role || !DASHBOARD_ROLES.has(role)) {
    return c.json({ message: 'role must be owner, admin or developer' }, 400)
  }
  const result = await updateDashboardUserRole(c.req.param('username'), role as DashboardRole)
  if (result.lastOwner) {
    return c.json({ message: 'the last owner cannot be demoted' }, 400)
  }
  if (!result.updated) return c.json({ message: 'user not found' }, 404)
  return c.json({})
})

app.delete('/platform/dashboard-users/:username', async (c) => {
  if (!canAdminister(c)) {
    return c.json({ message: 'only owners and admins can manage users' }, 403)
  }
  const result = await deleteDashboardUser(c.req.param('username'))
  if (result.lastOwner) {
    return c.json({ message: 'the last owner cannot be deleted' }, 400)
  }
  if (!result.deleted) return c.json({ message: 'user not found' }, 404)
  return c.json({})
})

app.get('/platform/dashboard-users/invitations', async (c) => {
  return c.json(await listInvitations())
})

app.post('/platform/dashboard-users/invitations', async (c) => {
  if (!canAdminister(c)) {
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
  const invitedEmail = typeof payload?.invited_email === 'string' ? payload.invited_email : ''
  if (invitedEmail.length > 320) {
    return c.json({ message: 'invited_email is too long' }, 400)
  }
  const identity = requestIdentity(c)
  const { invitation, token } = await createInvitation({
    role: role as DashboardRole,
    invitedBy: identity?.username ?? 'service',
    invitedEmail,
  })
  // The raw token is only returned here, once; the DB stores its hash.
  return c.json({ ...invitation, token }, 201)
})

app.delete('/platform/dashboard-users/invitations/:id', async (c) => {
  if (!canAdminister(c)) {
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
  return c.json(await getPostgrestConfig())
})

app.patch('/platform/projects/:ref/config/postgrest', async (c) => {
  const payload = await c.req.json<{
    db_schema?: string
    max_rows?: number
    db_extra_search_path?: string
    db_pool?: number | null
  }>()
  const patch: Parameters<typeof updatePostgrestConfig>[0] = {}
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
  return c.json(await updatePostgrestConfig(patch))
})

// -- Postgres configuration ---------------------------------------------

app.get('/platform/projects/:ref/config/database/postgres', async (c) => {
  return c.json(await getPostgresConfig())
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
    const result = await updatePostgresConfig(patch)
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
  await syncEnvFile()
  // PostgREST reads its trusted key set from a file this service owns, so it
  // has to exist (with the stack's own keys) before PostgREST starts.
  await syncThirdPartyJwks()
  if (env.functionsDir) await syncFunctionManifest()
  serve({ fetch: app.fetch, port: env.port }, (info) => {
    console.log(`management-api listening on :${info.port}`)
  })
  // Bring project stacks back up after a host/daemon restart, in background.
  void resumeProjects().catch((err) => console.error('resuming projects failed:', err))
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
