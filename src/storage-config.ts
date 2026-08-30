import { env } from './env.js'
import { getProject } from './projects-store.js'

/**
 * Storage configuration in the shape of the platform `StorageConfigResponse`.
 * Self-hosted storage reads its configuration from container environment
 * variables, so this is read-only: values are derived from the stack's env
 * (default project) or from the generated per-project compose files.
 */
export type StorageConfig = {
  fileSizeLimit: number
  features: {
    imageTransformation: { enabled: boolean }
    s3Protocol: { enabled: boolean }
    icebergCatalog: { enabled: boolean; maxCatalogs: number; maxNamespaces: number; maxTables: number }
    vectorBuckets: { enabled: boolean; maxBuckets: number; maxIndexes: number }
    purgeCache: { enabled: boolean }
  }
  capabilities: { iceberg_catalog: boolean; list_v2: boolean }
  databasePoolMode: string
  external: { upstreamTarget: 'main' }
  migrationVersion: string
}

export type S3ProtocolInfo = {
  enabled: boolean
  access_key_id: string | null
  secret_access_key: string | null
}

function buildConfig(input: {
  fileSizeLimit: number
  imageTransformation: boolean
  s3Protocol: boolean
  vectorBuckets: boolean
}): StorageConfig {
  return {
    fileSizeLimit: input.fileSizeLimit,
    features: {
      imageTransformation: { enabled: input.imageTransformation },
      s3Protocol: { enabled: input.s3Protocol },
      icebergCatalog: { enabled: false, maxCatalogs: 0, maxNamespaces: 0, maxTables: 0 },
      vectorBuckets: { enabled: input.vectorBuckets, maxBuckets: 10, maxIndexes: 20 },
      purgeCache: { enabled: false },
    },
    capabilities: { iceberg_catalog: false, list_v2: true },
    databasePoolMode: 'single_use',
    external: { upstreamTarget: 'main' },
    migrationVersion: 'latest',
  }
}

/** File size limit hardcoded in the generated per-project compose files. */
const PROJECT_FILE_SIZE_LIMIT = 52428800

export async function getStorageConfig(ref: string): Promise<StorageConfig | null> {
  if (ref === 'default') {
    return buildConfig({
      fileSizeLimit: env.storageFileSizeLimit,
      imageTransformation: true,
      s3Protocol: Boolean(env.s3ProtocolAccessKeyId && env.s3ProtocolAccessKeySecret),
      vectorBuckets: env.storageVectorsEnabled,
    })
  }
  const project = await getProject(ref)
  if (!project || project.kind !== 'compose') return null
  return buildConfig({
    fileSizeLimit: PROJECT_FILE_SIZE_LIMIT,
    imageTransformation: false,
    s3Protocol: Boolean(project.secrets?.s3_access_key_id && project.secrets?.s3_access_key_secret),
    vectorBuckets: env.storageVectorsEnabled,
  })
}

export async function getS3ProtocolInfo(ref: string): Promise<S3ProtocolInfo | null> {
  if (ref === 'default') {
    const enabled = Boolean(env.s3ProtocolAccessKeyId && env.s3ProtocolAccessKeySecret)
    return {
      enabled,
      access_key_id: enabled ? env.s3ProtocolAccessKeyId : null,
      secret_access_key: enabled ? env.s3ProtocolAccessKeySecret : null,
    }
  }
  const project = await getProject(ref)
  if (!project || project.kind !== 'compose') return null
  const keyId = project.secrets?.s3_access_key_id ?? null
  const keySecret = project.secrets?.s3_access_key_secret ?? null
  const enabled = Boolean(keyId && keySecret)
  return {
    enabled,
    access_key_id: enabled ? keyId : null,
    secret_access_key: enabled ? keySecret : null,
  }
}
