import { AUTH_CONFIG_KEYS } from './auth-config-keys.js'
import type { ConfigValue } from './store.js'

/**
 * GoTrue defaults for keys whose zero value would be misleading or would
 * fail the dashboard's client-side validation. Values mirror the defaults
 * in supabase/auth (internal/conf/configuration.go).
 */
const KNOWN_DEFAULTS: Record<string, ConfigValue> = {
  CUSTOM_OAUTH_ENABLED: true,
  CUSTOM_OAUTH_MAX_PROVIDERS: 0,
  EXTERNAL_EMAIL_ENABLED: true,
  JWT_EXP: 3600,
  MAILER_OTP_EXP: 86400,
  MAILER_OTP_LENGTH: 6,
  MFA_MAX_ENROLLED_FACTORS: 10,
  MFA_TOTP_ENROLL_ENABLED: true,
  MFA_TOTP_VERIFY_ENABLED: true,
  PASSWORD_MIN_LENGTH: 6,
  RATE_LIMIT_ANONYMOUS_USERS: 30,
  RATE_LIMIT_EMAIL_SENT: 30,
  RATE_LIMIT_OTP: 30,
  RATE_LIMIT_SMS_SENT: 30,
  RATE_LIMIT_TOKEN_REFRESH: 150,
  RATE_LIMIT_VERIFY: 30,
  RATE_LIMIT_WEB3: 30,
  SECURITY_REFRESH_TOKEN_REUSE_INTERVAL: 10,
  SESSIONS_SINGLE_PER_USER: false,
  SITE_URL: 'http://localhost:3000',
  SMS_MAX_FREQUENCY: 60,
  SMS_OTP_EXP: 60,
  SMS_OTP_LENGTH: 6,
  SMS_PROVIDER: 'twilio',
  SMS_TEMPLATE: 'Your code is {{ .Code }}',
  SMTP_MAX_FREQUENCY: 60,
  SMTP_PORT: '587',
}

/**
 * A complete GoTrue configuration response: every known key is present so
 * dashboard forms never initialize fields from `undefined` (which breaks
 * dirty-state tracking and zod validation on submit). Type-appropriate
 * zero values are used unless a real GoTrue default is known.
 */
export function defaultAuthConfig(): Record<string, ConfigValue> {
  const out: Record<string, ConfigValue> = {}
  for (const [key, type] of Object.entries(AUTH_CONFIG_KEYS)) {
    if (type === 'boolean') out[key] = false
    else if (type === 'number') out[key] = 0
    else out[key] = ''
  }
  return { ...out, ...KNOWN_DEFAULTS }
}
