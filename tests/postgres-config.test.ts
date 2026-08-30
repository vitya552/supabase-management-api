import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

process.env.DATABASE_URL ??= 'postgres://unused'
process.env.MANAGEMENT_API_TOKEN ??= 'unused'
process.env.VAULT_ENC_KEY ??= 'test-encryption-key'

const { isManagedGuc, validateGucValue } = await import('../src/postgres-config.js')

describe('isManagedGuc', () => {
  it('accepts managed settings', () => {
    assert.equal(isManagedGuc('statement_timeout'), true)
    assert.equal(isManagedGuc('max_connections'), true)
    assert.equal(isManagedGuc('log_connections'), true)
  })

  it('rejects unknown or dangerous settings', () => {
    assert.equal(isManagedGuc('archive_command'), false)
    assert.equal(isManagedGuc('ssl_key_file'), false)
    assert.equal(isManagedGuc("statement_timeout'; drop table x; --"), false)
    assert.equal(isManagedGuc(''), false)
  })
})

describe('validateGucValue', () => {
  it('validates value types', () => {
    assert.equal(validateGucValue('statement_timeout', '60000ms'), null)
    assert.equal(validateGucValue('max_connections', 120), null)
    assert.equal(validateGucValue('log_connections', true), null)
  })

  it('rejects wrong types', () => {
    assert.ok(validateGucValue('max_connections', 'lots'))
    assert.ok(validateGucValue('log_connections', 'yes'))
    assert.ok(validateGucValue('unknown_setting', 1))
  })
})
