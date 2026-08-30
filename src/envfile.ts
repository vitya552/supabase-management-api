import { mkdir, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'

import { AUTH_CONFIG_KEYS } from './auth-config-keys.js'
import { env } from './env.js'
import { type ConfigValue, getAllConfig, getAllEmailTemplates } from './store.js'

export const MANAGED_ENV_FILE = '90-managed.env'

/**
 * Keys that are stored as plain numbers by the platform API but read by
 * GoTrue as Go durations, with the unit the dashboard uses for each.
 */
const DURATION_KEYS: Record<string, 'hours' | 'seconds'> = {
  SESSIONS_TIMEBOX: 'hours',
  SESSIONS_INACTIVITY_TIMEOUT: 'hours',
  SMTP_MAX_FREQUENCY: 'seconds',
  SMS_MAX_FREQUENCY: 'seconds',
  MFA_PHONE_MAX_FREQUENCY: 'seconds',
}

/** MAILER_TEMPLATES_<TYPE>_CONTENT keys are materialized as template URLs. */
const TEMPLATE_CONTENT_RE = /^MAILER_TEMPLATES_([A-Z0-9_]+)_CONTENT$/

/** EXTERNAL_<PROVIDER>_ENABLED keys whose provider needs a redirect URI. */
const EXTERNAL_ENABLED_RE = /^EXTERNAL_([A-Z0-9_]+)_ENABLED$/
const NO_REDIRECT_URI_PROVIDERS = new Set([
  'EMAIL',
  'PHONE',
  'ANONYMOUS_USERS',
  'WEB3_ETHEREUM',
  'WEB3_SOLANA',
])

export function templateTypeFromConfigKey(key: string): string | null {
  const match = key.match(TEMPLATE_CONTENT_RE)
  return match ? match[1].toLowerCase() : null
}

function escapeEnvValue(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}"`
}

function serializeValue(key: string, value: ConfigValue): string | null {
  if (value === null) return null
  const durationUnit = DURATION_KEYS[key]
  if (durationUnit !== undefined && typeof value === 'number') {
    // GoTrue treats a zero duration as invalid; omit the line so the
    // built-in default ("never") applies.
    if (value === 0) return null
    return durationUnit === 'hours' ? `${value}h` : `${value}s`
  }
  return String(value)
}

export function renderEnvFile(
  config: Record<string, ConfigValue>,
  templateTypes: string[]
): string {
  const lines: string[] = [
    '# Managed by supabase management-api. Do not edit by hand -',
    '# this file is rewritten on every configuration change and is',
    '# live-reloaded by GoTrue (auth --config-dir).',
  ]

  const sortedKeys = Object.keys(config).sort()
  for (const key of sortedKeys) {
    if (!(key in AUTH_CONFIG_KEYS)) continue
    if (TEMPLATE_CONTENT_RE.test(key)) continue

    const serialized = serializeValue(key, config[key])
    if (serialized === null) continue
    lines.push(`GOTRUE_${key}=${escapeEnvValue(serialized)}`)

    // Providers configured at runtime also need their redirect URI set,
    // which the platform derives instead of storing.
    const providerMatch = key.match(EXTERNAL_ENABLED_RE)
    if (
      providerMatch &&
      config[key] === true &&
      !NO_REDIRECT_URI_PROVIDERS.has(providerMatch[1]) &&
      env.authCallbackUrl
    ) {
      lines.push(
        `GOTRUE_EXTERNAL_${providerMatch[1]}_REDIRECT_URI=${escapeEnvValue(env.authCallbackUrl)}`
      )
    }
  }

  for (const templateType of [...templateTypes].sort()) {
    // The type becomes part of an env variable name, so anything that is not a
    // plain identifier is skipped rather than escaped.
    if (!/^[a-z0-9_]+$/.test(templateType)) continue
    lines.push(
      `GOTRUE_MAILER_TEMPLATES_${templateType.toUpperCase()}=${escapeEnvValue(
        `${env.selfUrl}/templates/${templateType}`
      )}`
    )
  }

  return lines.join('\n') + '\n'
}

/** Regenerates the watched env file from the database state. */
export async function syncEnvFile(): Promise<void> {
  const [config, templates] = await Promise.all([getAllConfig(), getAllEmailTemplates()])
  const content = renderEnvFile(
    config,
    templates.map((t) => t.template_type)
  )

  const target = join(env.authConfigDir, MANAGED_ENV_FILE)
  await mkdir(dirname(target), { recursive: true })
  // Write-then-rename so GoTrue never reads a partially written file.
  const tmp = `${target}.tmp`
  await writeFile(tmp, content, 'utf8')
  await rename(tmp, target)
}
