import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

process.env.MANAGEMENT_API_TOKEN = process.env.MANAGEMENT_API_TOKEN || 'test-token'
process.env.DATABASE_URL = process.env.DATABASE_URL || 'postgres://localhost:5432/test'
process.env.VAULT_ENC_KEY = process.env.VAULT_ENC_KEY || 'test-encryption-key'
process.env.DASHBOARD_USERNAME = 'admin'
process.env.DASHBOARD_PASSWORD = 'test-password'

const {
  createSessionToken,
  getCookie,
  isValidBasicAuthHeader,
  isValidCredentials,
  isValidSessionToken,
  sanitizeRedirectPath,
} = await import('../src/dashboard-auth.js')

describe('session tokens', () => {
  it('round-trips a freshly created token', () => {
    const token = createSessionToken()
    assert.equal(isValidSessionToken(token), true)
  })

  it('rejects expired tokens', () => {
    const token = createSessionToken(Date.now() - 9 * 60 * 60 * 1000)
    assert.equal(isValidSessionToken(token), false)
  })

  it('rejects tampered tokens', () => {
    const token = createSessionToken()
    const [expiresAt, signature] = token.split('.')
    assert.equal(isValidSessionToken(`${Number(expiresAt) + 60}.${signature}`), false)
    assert.equal(isValidSessionToken('garbage'), false)
    assert.equal(isValidSessionToken(''), false)
  })
})

describe('credentials', () => {
  it('accepts configured credentials', () => {
    assert.equal(isValidCredentials('admin', 'test-password'), true)
    assert.equal(isValidCredentials('admin', 'wrong'), false)
    assert.equal(isValidCredentials('other', 'test-password'), false)
  })

  it('validates basic auth headers', () => {
    const good = `Basic ${Buffer.from('admin:test-password').toString('base64')}`
    const bad = `Basic ${Buffer.from('admin:wrong').toString('base64')}`
    assert.equal(isValidBasicAuthHeader(good), true)
    assert.equal(isValidBasicAuthHeader(bad), false)
    assert.equal(isValidBasicAuthHeader('Bearer abc'), false)
  })
})

describe('helpers', () => {
  it('parses cookies', () => {
    assert.equal(getCookie('a=1; sb-dashboard-session=tok; b=2', 'sb-dashboard-session'), 'tok')
    assert.equal(getCookie('a=1', 'sb-dashboard-session'), null)
  })

  it('sanitizes redirect paths', () => {
    assert.equal(sanitizeRedirectPath('/project/default'), '/project/default')
    assert.equal(sanitizeRedirectPath('//evil.example'), '/')
    assert.equal(sanitizeRedirectPath('https://evil.example'), '/')
    assert.equal(sanitizeRedirectPath(undefined), '/')
  })
})
