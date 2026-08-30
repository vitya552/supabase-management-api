import http from 'node:http'
import type { IncomingMessage } from 'node:http'
import type { Duplex } from 'node:stream'

import type { Context } from 'hono'

import { getProject } from './projects-store.js'
import { containerName, realtimeContainerName } from './provisioner.js'

/** Gateway path prefix -> project service (container suffix, port). */
const SERVICE_TARGETS: Record<string, { service: string; port: number }> = {
  rest: { service: 'rest', port: 3000 },
  auth: { service: 'auth', port: 9999 },
  storage: { service: 'storage', port: 5000 },
  functions: { service: 'functions', port: 9000 },
  realtime: { service: 'realtime', port: 4000 },
}

/**
 * Maps a `/proj/:ref/<service>/v1/...` gateway path to the target service
 * URL, mirroring the main gateway's route table (Realtime's `/realtime/v1/api`
 * maps to `/api` and everything else under `/realtime/v1/` to `/socket/`).
 * Returns null when the path doesn't address a known project service.
 */
export function resolveProjectServiceUrl(ref: string, pathname: string): URL | null {
  const prefix = `/proj/${ref}/`
  if (!pathname.startsWith(prefix)) return null
  const remainder = pathname.slice(prefix.length)
  const [serviceName = '', apiVersion, ...restParts] = remainder.split('/')
  const target = SERVICE_TARGETS[serviceName]
  if (!target || apiVersion !== 'v1') return null

  if (serviceName === 'realtime') {
    const rest = restParts[0] === 'api' ? restParts : ['socket', ...restParts]
    return new URL(`http://${realtimeContainerName(ref)}:${target.port}/${rest.join('/')}`)
  }
  return new URL(
    `http://${containerName(ref, target.service)}:${target.port}/${restParts.join('/')}`
  )
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

const UPGRADE_PATH_RE = /^\/proj\/([a-z][a-z0-9]{1,29})\/realtime\/v1\//

/**
 * HTTP Upgrade (websocket) handler for `/proj/:ref/realtime/v1/*`. The
 * fetch-based proxy above cannot carry protocol upgrades, so websocket
 * handshakes are relayed at the socket level instead.
 */
export function handleProjectUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
  const url = new URL(req.url ?? '/', 'http://internal')
  const match = UPGRADE_PATH_RE.exec(url.pathname)
  if (!match) {
    socket.destroy()
    return
  }
  const ref = match[1]

  void (async () => {
    const project = await getProject(ref)
    if (!project || project.kind !== 'compose' || project.status !== 'ACTIVE_HEALTHY') {
      socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n')
      return
    }
    const targetUrl = resolveProjectServiceUrl(ref, url.pathname)
    if (targetUrl === null) {
      socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n')
      return
    }
    targetUrl.search = url.search

    const headers: Record<string, string | string[] | undefined> = { ...req.headers }
    delete headers.host
    delete headers['content-length']

    const upstream = http.request(targetUrl, { headers })

    upstream.on('upgrade', (upstreamRes, upstreamSocket, upstreamHead) => {
      const lines = ['HTTP/1.1 101 Switching Protocols']
      for (let i = 0; i < upstreamRes.rawHeaders.length; i += 2) {
        lines.push(`${upstreamRes.rawHeaders[i]}: ${upstreamRes.rawHeaders[i + 1]}`)
      }
      socket.write(lines.join('\r\n') + '\r\n\r\n')
      if (upstreamHead.length > 0) socket.write(upstreamHead)
      if (head.length > 0) upstreamSocket.write(head)
      upstreamSocket.pipe(socket)
      socket.pipe(upstreamSocket)
      const closeBoth = () => {
        upstreamSocket.destroy()
        socket.destroy()
      }
      upstreamSocket.on('error', closeBoth)
      socket.on('error', closeBoth)
      upstreamSocket.on('close', () => socket.destroy())
      socket.on('close', () => upstreamSocket.destroy())
    })

    upstream.on('response', (response) => {
      // Upstream refused the upgrade: relay the status and close.
      socket.end(`HTTP/1.1 ${response.statusCode ?? 502} ${response.statusMessage ?? ''}\r\nConnection: close\r\n\r\n`)
      response.destroy()
    })

    upstream.on('error', () => socket.destroy())
    upstream.end()
  })().catch(() => socket.destroy())
}

/**
 * Proxies `/proj/:ref/<service>/v1/*` to the matching service of the
 * project's stack. The services authenticate requests themselves (JWTs
 * signed with the project's own secret), like behind the main gateway.
 */
export async function proxyProjectRequest(c: Context): Promise<Response> {
  const ref = c.req.param('ref') ?? ''
  if (!REF_RE.test(ref)) return c.json({ message: 'invalid project ref' }, 400)

  const url = new URL(c.req.url)
  const targetUrl = resolveProjectServiceUrl(ref, url.pathname)
  if (targetUrl === null) return c.json({ message: 'not found' }, 404)

  const project = await getProject(ref)
  if (!project || project.kind !== 'compose') {
    return c.json({ message: 'project not found' }, 404)
  }
  if (project.status !== 'ACTIVE_HEALTHY') {
    return c.json({ message: `project is ${project.status}` }, 503)
  }

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
