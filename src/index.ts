import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { logger } from 'hono/logger'

import { AUTH_CONFIG_KEYS } from './auth-config-keys.js'
import { baselineConfig } from './baseline.js'
import { renderReactEmail } from './emails.js'
import { env } from './env.js'
import { syncEnvFile, templateTypeFromConfigKey } from './envfile.js'
import {
  deleteFunctionFiles,
  type FunctionFile,
  isValidSlug,
  writeFunctionFiles,
  writeSecretsFile,
} from './functions.js'
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

// Everything under /platform requires the management token.
app.use('/platform/*', async (c, next) => {
  const auth = c.req.header('authorization') ?? ''
  if (auth !== `Bearer ${env.apiToken}`) {
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
  return { ...baselineConfig(), ...(await getAllConfig()) }
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

app.post('/platform/auth/:ref/templates/:template/reset', async (c) => {
  const template = c.req.param('template').toLowerCase()
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
  const template = c.req.param('template').toLowerCase()
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
  const template = await getEmailTemplate(c.req.param('template').toLowerCase())
  if (!template || template.source_format !== 'react') {
    return c.json({ message: 'react template not found' }, 404)
  }
  return c.json(template)
})

// -- Edge Functions -----------------------------------------------------

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
  for (const entry of form.getAll('file')) {
    if (typeof entry === 'string') continue
    files.push({ name: entry.name, content: await entry.text() })
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
  return c.json(functionResponse(fn))
})

app.delete('/platform/projects/:ref/functions/:slug', async (c) => {
  const slug = c.req.param('slug')
  if (!isValidSlug(slug)) return c.json({ message: `invalid function slug: ${slug}` }, 400)
  await deleteFunctionFiles(env.functionsDir, slug)
  await deleteEdgeFunction(slug)
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
  return c.json(
    secrets.map((secret) => ({
      name: secret.name,
      value: secret.value,
      updated_at: new Date(secret.updated_at).toISOString(),
    }))
  )
})

const SECRET_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/

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

async function main() {
  await migrate()
  await syncEnvFile()
  serve({ fetch: app.fetch, port: env.port }, (info) => {
    console.log(`management-api listening on :${info.port}`)
  })
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
