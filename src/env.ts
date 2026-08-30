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

  /** Asymmetric key set of the stack, when configured (JWT_JWKS). */
  jwtJwks: process.env.JWT_JWKS ?? '',

  /**
   * File (shared with the postgrest service through a volume, referenced by
   * `PGRST_JWT_SECRET=@<path>`) holding the JWK set PostgREST trusts. Written
   * instead of a role setting so the symmetric key never lands in the
   * database catalog, which every role can read.
   */
  postgrestJwksFile: process.env.PGRST_JWKS_FILE ?? '/etc/postgrest-runtime/jwt-secret.json',

  /**
   * Dashboard login credentials, checked by the gateway via ext_authz.
   * Unset disables the dashboard session endpoints.
   */
  dashboardUsername: process.env.DASHBOARD_USERNAME ?? '',
  dashboardPassword: process.env.DASHBOARD_PASSWORD ?? '',

  /**
   * Key signing dashboard session cookies. Kept separate from the management
   * token so leaking one does not grant the other.
   */
  dashboardSessionSecret: process.env.DASHBOARD_SESSION_SECRET ?? '',

  /** Set when the stack is served over HTTPS, so session cookies get `Secure`. */
  publicUrl: process.env.SUPABASE_PUBLIC_URL ?? '',

  /**
   * Key used to encrypt secret values at rest (AES-256-GCM). Falls back to
   * VAULT_ENC_KEY so the standard self-hosted .env works out of the box.
   */
  encryptionKey: process.env.MANAGEMENT_ENC_KEY || required('VAULT_ENC_KEY'),

  /**
   * Multi-project provisioning. PROJECTS_DIR is where project stacks are
   * materialized inside this container; PROJECTS_HOST_DIR is the same
   * directory as seen by the host docker daemon (needed because generated
   * compose files bind-mount host paths). Unset disables provisioning.
   */
  projectsDir: process.env.PROJECTS_DIR ?? '',
  projectsHostDir: process.env.PROJECTS_HOST_DIR ?? '',

  /** Copy source for per-project database init scripts (volumes/db). */
  dbInitDir: process.env.DB_INIT_DIR ?? '/mnt/db-init',

  /** Docker network shared with the main stack, joined by project stacks. */
  mainNetworkName: process.env.MAIN_NETWORK_NAME ?? 'supabase_default',

  /** Realtime service of the default stack (tenant admin + websocket host). */
  realtimeHost: process.env.REALTIME_HOST ?? 'realtime-dev.supabase-realtime',
  realtimePort: Number(process.env.REALTIME_PORT ?? 4000),

  /** Images used for per-project stacks; keep in sync with docker-compose.yml. */
  projectImages: {
    postgres: process.env.PROJECT_POSTGRES_IMAGE ?? 'supabase/postgres:17.6.1.136',
    postgrest: process.env.PROJECT_POSTGREST_IMAGE ?? 'postgrest/postgrest:v14.12',
    gotrue: process.env.PROJECT_GOTRUE_IMAGE ?? 'supabase/gotrue:v2.189.0',
    storage: process.env.PROJECT_STORAGE_IMAGE ?? 'supabase/storage-api:v1.60.4',
    edgeRuntime: process.env.PROJECT_EDGE_RUNTIME_IMAGE ?? 'supabase/edge-runtime:v1.74.0',
    realtime: process.env.PROJECT_REALTIME_IMAGE ?? 'supabase/realtime:v2.102.3',
  },
}
