import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { logger } from 'hono/logger'

import { AUTH_CONFIG_KEYS } from './auth-config-keys.js'
import { baselineConfig } from './baseline.js'
import { renderReactEmail } from './emails.js'
import { env } from './env.js'
import { syncEnvFile, templateTypeFromConfigKey } from './envfile.js'
import {
  type ConfigValue,
  deleteConfig,
  deleteEmailTemplate,
  getAllConfig,
  getEmailTemplate,
  migrate,
  upsertConfig,
  upsertEmailTemplate,
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
