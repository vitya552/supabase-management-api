import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { test } from 'node:test'

import { generateTotpSecret, totpUri, verifyTotpCode } from '../src/totp.js'

// Reference TOTP implementation (RFC 6238, SHA1, 6 digits, 30s period) used
// to cross-check the module under test.
function referenceCode(secretBase32: string, timeMs: number): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = 0
  let value = 0
  const bytes: number[] = []
  for (const char of secretBase32) {
    value = (value << 5) | alphabet.indexOf(char)
    bits += 5
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  const counter = Math.floor(timeMs / 1000 / 30)
  const message = Buffer.alloc(8)
  message.writeBigUInt64BE(BigInt(counter))
  const digest = createHmac('sha1', Buffer.from(bytes)).update(message).digest()
  const offset = digest[digest.length - 1] & 0x0f
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3]
  return String(binary % 1_000_000).padStart(6, '0')
}

test('generated secrets are 32-char base32', () => {
  const secret = generateTotpSecret()
  assert.match(secret, /^[A-Z2-7]{32}$/)
})

test('accepts the current reference code and codes one period away', () => {
  const secret = generateTotpSecret()
  const now = Date.now()
  assert.equal(verifyTotpCode(secret, referenceCode(secret, now), now), true)
  assert.equal(verifyTotpCode(secret, referenceCode(secret, now - 30_000), now), true)
  assert.equal(verifyTotpCode(secret, referenceCode(secret, now + 30_000), now), true)
})

test('rejects stale, malformed and wrong codes', () => {
  const secret = generateTotpSecret()
  const now = Date.now()
  assert.equal(verifyTotpCode(secret, referenceCode(secret, now - 90_000), now), false)
  assert.equal(verifyTotpCode(secret, 'abcdef', now), false)
  assert.equal(verifyTotpCode(secret, '12345', now), false)
  const current = referenceCode(secret, now)
  const wrong = current === '000000' ? '000001' : '000000'
  assert.equal(verifyTotpCode(secret, wrong, now), false)
})

test('otpauth uri embeds issuer, account and secret', () => {
  const uri = totpUri('ABC234', 'alice', 'Supabase Studio')
  assert.equal(
    uri,
    'otpauth://totp/Supabase%20Studio:alice?secret=ABC234&issuer=Supabase%20Studio&algorithm=SHA1&digits=6&period=30'
  )
})
