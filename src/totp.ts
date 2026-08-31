import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const PERIOD_SECONDS = 30
const DIGITS = 6

export function base32Encode(buffer: Buffer): string {
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of buffer) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31]
  return out
}

function base32Decode(encoded: string): Buffer {
  let bits = 0
  let value = 0
  const out: number[] = []
  for (const char of encoded.toUpperCase().replace(/=+$/, '')) {
    const index = BASE32_ALPHABET.indexOf(char)
    if (index === -1) throw new Error('invalid base32 secret')
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Buffer.from(out)
}

export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20))
}

function totpCodeAt(secret: string, counter: number): string {
  const message = Buffer.alloc(8)
  message.writeBigUInt64BE(BigInt(counter))
  const digest = createHmac('sha1', base32Decode(secret)).update(message).digest()
  const offset = digest[digest.length - 1] & 0x0f
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3]
  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0')
}

/** Verifies a TOTP code, allowing one period of clock drift in each direction. */
export function verifyTotpCode(secret: string, code: string, now = Date.now()): boolean {
  if (!/^\d{6}$/.test(code)) return false
  const counter = Math.floor(now / 1000 / PERIOD_SECONDS)
  const provided = Buffer.from(code)
  for (const window of [0, -1, 1]) {
    const expected = Buffer.from(totpCodeAt(secret, counter + window))
    if (expected.length === provided.length && timingSafeEqual(expected, provided)) return true
  }
  return false
}

/** otpauth:// URI encoding the secret for authenticator apps. */
export function totpUri(secret: string, accountName: string, issuer: string): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${PERIOD_SECONDS}`
}
