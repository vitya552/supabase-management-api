import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'

import { env } from './env.js'

const ENC_PREFIX = 'enc:v1:'

function encryptionKey(): Buffer {
  // Normalize the configured key to 32 bytes for AES-256-GCM.
  return createHash('sha256').update(`management-enc:${env.encryptionKey}`).digest()
}

export function encryptString(plaintext: string): string {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', encryptionKey(), iv)
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return `${ENC_PREFIX}${iv.toString('base64')}:${tag.toString('base64')}:${ciphertext.toString('base64')}`
}

export function isEncrypted(value: string): boolean {
  return value.startsWith(ENC_PREFIX)
}

export function decryptString(value: string): string {
  if (!isEncrypted(value)) return value
  const [ivB64, tagB64, ctB64] = value.slice(ENC_PREFIX.length).split(':')
  if (!ivB64 || !tagB64 || !ctB64) throw new Error('malformed encrypted value')
  const decipher = createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(ivB64, 'base64'))
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'))
  return Buffer.concat([
    decipher.update(Buffer.from(ctB64, 'base64')),
    decipher.final(),
  ]).toString('utf8')
}

const SENSITIVE_KEY_RE = /(SECRET|SECRETS|PASSWORD|PASS|AUTH_TOKEN|ACCESS_KEY|API_KEY|PRIVATE_KEY)$/

export function isSensitiveConfigKey(key: string): boolean {
  return SENSITIVE_KEY_RE.test(key)
}
