import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { logger } from 'hono/logger'
import { createHash, timingSafeEqual } from 'node:crypto'

import { AUTH_CONFIG_KEYS } from './auth-config-keys.js'
import { baselineConfig } from './baseline.js'
import {
  createSessionToken,
  getCookie,
  isLoginRateLimited,
  isValidBasicAuthHeader,
  isValidCredentials,
  isValidSessionToken,
  resetLoginRateLimit,
  sanitizeRedirectPath,
  sessionCookie,
  SESSION_COOKIE,
} from './dashboard-auth.js'
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
  const clientKey =
    c.req.header('x-forwarded-for')?.split(',')[0].trim() ||
    c.req.header('x-envoy-external-address') ||
    'unknown'
  if (isLoginRateLimited(clientKey)) {
    return c.json({ message: 'Too many sign in attempts, try again later' }, 429)
  }

  const payload = await c.req.json<{ username?: string; password?: string }>().catch(() => null)
  const username = payload?.username ?? ''
  const password = payload?.password ?? ''

  if (!isValidCredentials(username, password)) {
    return c.json({ message: 'Invalid username or password' }, 401)
  }

  resetLoginRateLimit(clientKey)
  c.header('Set-Cookie', sessionCookie(createSessionToken()))
  return c.json({ message: 'ok' })
})

app.post('/dashboard-auth/logout', (c) => {
  c.header('Set-Cookie', sessionCookie(null))
  return c.json({ message: 'ok' })
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
  await syncEnvFile()
  // PostgREST reads its trusted key set from a file this service owns, so it
  // has to exist (with the stack's own keys) before PostgREST starts.
  await syncThirdPartyJwks()
  if (env.functionsDir) await syncFunctionManifest()
  serve({ fetch: app.fetch, port: env.port }, (info) => {
    console.log(`management-api listening on :${info.port}`)
  })
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
