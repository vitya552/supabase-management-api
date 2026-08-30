import assert from 'node:assert/strict'
import { test } from 'node:test'

process.env.DATABASE_URL ??= 'postgres://unused'
process.env.MANAGEMENT_API_TOKEN ??= 'unused'
process.env.VAULT_ENC_KEY ??= 'test-encryption-key'

const { resolveProjectServiceUrl } = await import('../src/project-proxy.js')

test('maps rest paths to the project rest container', () => {
  const url = resolveProjectServiceUrl('abc', '/proj/abc/rest/v1/todos')
  assert.equal(url?.toString(), 'http://sbproj-abc-rest:3000/todos')
})

test('maps auth paths to the project auth container', () => {
  const url = resolveProjectServiceUrl('abc', '/proj/abc/auth/v1/token')
  assert.equal(url?.toString(), 'http://sbproj-abc-auth:9999/token')
})

test('maps storage paths to the project storage container', () => {
  const url = resolveProjectServiceUrl('abc', '/proj/abc/storage/v1/bucket')
  assert.equal(url?.toString(), 'http://sbproj-abc-storage:5000/bucket')
})

test('maps realtime api paths to /api on the realtime container', () => {
  const url = resolveProjectServiceUrl('abc', '/proj/abc/realtime/v1/api/tenants')
  assert.equal(url?.toString(), 'http://realtime-dev.sbproj-abc-realtime:4000/api/tenants')
})

test('maps realtime websocket paths to /socket on the realtime container', () => {
  const url = resolveProjectServiceUrl('abc', '/proj/abc/realtime/v1/websocket')
  assert.equal(url?.toString(), 'http://realtime-dev.sbproj-abc-realtime:4000/socket/websocket')
})

test('rejects unknown services and non-v1 paths', () => {
  assert.equal(resolveProjectServiceUrl('abc', '/proj/abc/db/v1/x'), null)
  assert.equal(resolveProjectServiceUrl('abc', '/proj/abc/rest/v2/x'), null)
  assert.equal(resolveProjectServiceUrl('abc', '/proj/other/rest/v1/x'), null)
})
