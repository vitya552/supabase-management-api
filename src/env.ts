const required = (name: string): string => {
  const value = process.env[name]
  if (!value) throw new Error(`Missing required env var: ${name}`)
  return value
}

export const env = {
  port: Number(process.env.PORT ?? 8085),

  /** Postgres connection string used to persist managed configuration. */
  databaseUrl: required('DATABASE_URL'),

  /**
   * Bearer token required on all /platform endpoints. Studio's server-side
   * proxy injects it. Template endpoints (fetched by GoTrue) are public.
   */
  apiToken: required('MANAGEMENT_API_TOKEN'),

  /** Directory watched by GoTrue via `auth --config-dir`. */
  authConfigDir: process.env.AUTH_CONFIG_DIR ?? '/etc/auth-runtime',

  /**
   * Base URL under which this service is reachable *from the auth container*.
   * Used to build MAILER_TEMPLATES_* URLs.
   */
  selfUrl: process.env.SELF_URL ?? 'http://management-api:8085',

  /**
   * Shared edge functions volume (also mounted by edge-runtime). Unset
   * disables the edge-functions management endpoints.
   */
  functionsDir: process.env.FUNCTIONS_DIR ?? '',

  /** Env defaults for PostgREST config, mirroring the postgrest service. */
  pgrstDbSchemas: process.env.PGRST_DB_SCHEMAS ?? 'public,graphql_public,storage',
  pgrstDbMaxRows: Number(process.env.PGRST_DB_MAX_ROWS) || 1000,
  pgrstDbExtraSearchPath: process.env.PGRST_DB_EXTRA_SEARCH_PATH ?? 'public',

  /** OAuth callback URL advertised to providers (public URL of the stack). */
  authCallbackUrl:
    process.env.AUTH_CALLBACK_URL ??
    (process.env.API_EXTERNAL_URL ? `${process.env.API_EXTERNAL_URL}/auth/v1/callback` : ''),

  /**
   * The stack's JWT secret. Needed to keep first-party API keys working when
   * third-party auth integrations extend PostgREST's trusted key set.
   */
  jwtSecret: process.env.JWT_SECRET ?? '',

  /**
   * Dashboard login credentials, checked by the gateway via ext_authz.
   * Unset disables the dashboard session endpoints.
   */
  dashboardUsername: process.env.DASHBOARD_USERNAME ?? '',
  dashboardPassword: process.env.DASHBOARD_PASSWORD ?? '',
}
