import type { Context } from 'hono'

import { getProject } from './projects-store.js'
import { containerName } from './provisioner.js'

/** Gateway path prefix -> project service (container suffix, port). */
const SERVICE_TARGETS: Record<string, { service: string; port: number }> = {
  rest: { service: 'rest', port: 3000 },
  auth: { service: 'auth', port: 9999 },
  storage: { service: 'storage', port: 5000 },
  functions: { service: 'functions', port: 9000 },
}

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
  'content-length',
])

const REF_RE = /^[a-z][a-z0-9]{1,29}$/

/**
 * Proxies `/proj/:ref/<service>/v1/*` to the matching service of the
 * project's stack. The services authenticate requests themselves (JWTs
 * signed with the project's own secret), like behind the main gateway.
 */
export async function proxyProjectRequest(c: Context): Promise<Response> {
  const ref = c.req.param('ref') ?? ''
  if (!REF_RE.test(ref)) return c.json({ message: 'invalid project ref' }, 400)

  const url = new URL(c.req.url)
  const prefix = `/proj/${ref}/`
  if (!url.pathname.startsWith(prefix)) return c.json({ message: 'not found' }, 404)
  const remainder = url.pathname.slice(prefix.length)
  const [serviceName = '', apiVersion, ...restParts] = remainder.split('/')
  const target = SERVICE_TARGETS[serviceName]
  if (!target || apiVersion !== 'v1') return c.json({ message: 'not found' }, 404)

  const project = await getProject(ref)
  if (!project || project.kind !== 'compose') {
    return c.json({ message: 'project not found' }, 404)
  }
  if (project.status !== 'ACTIVE_HEALTHY') {
    return c.json({ message: `project is ${project.status}` }, 503)
  }

  const targetUrl = new URL(
    `http://${containerName(ref, target.service)}:${target.port}/${restParts.join('/')}`
  )
  targetUrl.search = url.search

  const headers = new Headers()
  c.req.raw.headers.forEach((value, key) => {
    if (!HOP_BY_HOP_HEADERS.has(key.toLowerCase())) headers.set(key, value)
  })
  headers.set('x-forwarded-host', url.host)
  headers.set('x-forwarded-proto', url.protocol.replace(':', ''))
  headers.set('x-forwarded-path', url.pathname)

  const method = c.req.method
  const hasBody = method !== 'GET' && method !== 'HEAD'

  try {
    const response = await fetch(targetUrl, {
      method,
      headers,
      body: hasBody ? c.req.raw.body : undefined,
      redirect: 'manual',
      // @ts-expect-error duplex is required by undici for streaming bodies
      duplex: hasBody ? 'half' : undefined,
    })

    const responseHeaders = new Headers()
    response.headers.forEach((value, key) => {
      if (!HOP_BY_HOP_HEADERS.has(key.toLowerCase())) responseHeaders.append(key, value)
    })
    return new Response(response.body, {
      status: response.status,
      headers: responseHeaders,
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return c.json({ message: `project service unreachable: ${message}` }, 502)
  }
}
