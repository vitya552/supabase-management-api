import assert from 'node:assert/strict'
import { afterEach, describe, it, mock } from 'node:test'

process.env.MANAGEMENT_API_TOKEN ??= 'test-token'
process.env.DATABASE_URL ??= 'postgres://localhost:5432/test'
process.env.VAULT_ENC_KEY ??= 'test-encryption-key'
process.env.JWT_SECRET ??= 'test-jwt-secret-with-at-least-32-characters'

const { pool } = await import('../src/store.js')
const {
  driftedFields,
  getRealtimeConfig,
  reconcileRealtimeConfig,
  startRealtimeReconciler,
  updateRealtimeConfig,
  validateRealtimeUpdates,
} = await import('../src/realtime-config.js')

type Call = { method: string; body: unknown }

function fakeRealtime(initial: Record<string, unknown>, options: { down?: boolean } = {}) {
  const tenant = { ...initial }
  const calls: Call[] = []
  mock.method(globalThis, 'fetch', async (_url: string | URL | Request, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    const body = init?.body ? JSON.parse(String(init.body)) : undefined
    calls.push({ method, body })
    if (options.down) throw new Error('ECONNREFUSED')
    if (method === 'PATCH') Object.assign(tenant, body.tenant)
    return new Response(JSON.stringify({ data: tenant }), { status: 200 })
  })
  return { tenant, calls, patches: () => calls.filter((c) => c.method === 'PATCH') }
}

function fakeStore(stored: Record<string, unknown> | null) {
  const writes: unknown[][] = []
  mock.method(pool, 'query', async (text: string, values?: unknown[]) => {
    if (text.startsWith('select config')) return { rows: stored ? [{ config: stored }] : [] }
    writes.push(values ?? [])
    return { rows: [] }
  })
  return { writes }
}

afterEach(() => mock.restoreAll())

describe('validateRealtimeUpdates', () => {
  it('accepts dashboard values', () => {
    assert.equal(
      validateRealtimeUpdates({ max_concurrent_users: 500, private_only: true, suspend: false }),
      null
    )
  })

  it('rejects wrong types', () => {
    assert.ok(validateRealtimeUpdates({ max_concurrent_users: '500' }))
    assert.ok(validateRealtimeUpdates({ max_events_per_second: 0 }))
    assert.ok(validateRealtimeUpdates({ max_payload_size_in_kb: 1.5 }))
    assert.ok(validateRealtimeUpdates({ private_only: 'yes' }))
  })
})

describe('driftedFields', () => {
  it('returns only saved fields the tenant does not match', () => {
    assert.deepEqual(
      driftedFields(
        { max_concurrent_users: 500, private_only: true },
        { max_concurrent_users: 200, private_only: true, max_payload_size_in_kb: 3000 }
      ),
      { max_concurrent_users: 500 }
    )
  })
})

describe('updateRealtimeConfig', () => {
  it('patches the tenant and remembers the applied fields', async () => {
    const rt = fakeRealtime({ max_concurrent_users: 200, private_only: false })
    const store = fakeStore(null)

    const result = await updateRealtimeConfig('default', {
      max_concurrent_users: 500,
      private_only: true,
      suspend: true,
      unknown_field: 1,
    })

    assert.deepEqual(rt.patches()[0].body, {
      tenant: { max_concurrent_users: 500, private_only: true },
    })
    assert.equal(store.writes.length, 1)
    assert.deepEqual(JSON.parse(store.writes[0][1] as string), {
      max_concurrent_users: 500,
      private_only: true,
    })
    assert.deepEqual(result, { max_concurrent_users: 500, private_only: true })
  })

  it('does not persist when Realtime rejects the patch', async () => {
    const rt = fakeRealtime({}, { down: true })
    const store = fakeStore(null)
    assert.equal(await updateRealtimeConfig('default', { max_concurrent_users: 500 }), null)
    assert.equal(rt.patches().length, 1)
    assert.equal(store.writes.length, 0)
  })

  it('is unavailable for unknown refs', async () => {
    fakeRealtime({})
    fakeStore(null)
    assert.equal(await updateRealtimeConfig('other', { max_concurrent_users: 500 }), null)
  })
})

describe('reconcileRealtimeConfig', () => {
  it('re-applies saved settings after the tenant was reseeded with defaults', async () => {
    const rt = fakeRealtime({ max_concurrent_users: 200, private_only: false })
    fakeStore({ max_concurrent_users: 500, private_only: true })

    const result = await reconcileRealtimeConfig('default')

    assert.deepEqual(rt.patches()[0].body, {
      tenant: { max_concurrent_users: 500, private_only: true },
    })
    assert.deepEqual(result, { max_concurrent_users: 500, private_only: true })
  })

  it('leaves a matching tenant alone', async () => {
    const rt = fakeRealtime({ max_concurrent_users: 500, private_only: true })
    fakeStore({ max_concurrent_users: 500 })
    await reconcileRealtimeConfig('default')
    assert.equal(rt.patches().length, 0)
  })

  it('does nothing without saved settings', async () => {
    const rt = fakeRealtime({ max_concurrent_users: 200 })
    fakeStore(null)
    assert.deepEqual(await reconcileRealtimeConfig('default'), { max_concurrent_users: 200 })
    assert.equal(rt.patches().length, 0)
  })

  it('reports unavailable when Realtime is down', async () => {
    const rt = fakeRealtime({}, { down: true })
    fakeStore({ max_concurrent_users: 500 })
    assert.equal(await reconcileRealtimeConfig('default'), null)
    assert.equal(rt.patches().length, 0)
  })

  it('backs the dashboard read so a reseeded tenant is healed on view', async () => {
    const rt = fakeRealtime({ max_concurrent_users: 200 })
    fakeStore({ max_concurrent_users: 500 })
    assert.deepEqual(await getRealtimeConfig('default'), { max_concurrent_users: 500 })
    assert.equal(rt.patches().length, 1)
  })
})

describe('startRealtimeReconciler', () => {
  it('reconciles immediately and keeps running on the interval', async () => {
    const rt = fakeRealtime({ max_concurrent_users: 200 })
    fakeStore({ max_concurrent_users: 500 })

    const timer = startRealtimeReconciler(async () => ['default'], 10)
    await new Promise((resolve) => setTimeout(resolve, 35))
    clearInterval(timer)

    assert.equal(rt.patches().length, 1)
    assert.ok(rt.calls.filter((c) => c.method === 'GET').length >= 3)
  })
})
