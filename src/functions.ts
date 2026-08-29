import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises'
import path from 'node:path'

export type FunctionFile = { name: string; content: string }

const SLUG_RE = /^[A-Za-z0-9_-]+$/

export function isValidSlug(slug: string): boolean {
  return SLUG_RE.test(slug) && slug !== 'main'
}

function assertSafeRelativePath(base: string, relative: string): string {
  const resolved = path.resolve(base, relative)
  if (!resolved.startsWith(path.resolve(base) + path.sep)) {
    throw new Error(`invalid file path: ${relative}`)
  }
  return resolved
}

/**
 * Writes a function's files under `<functionsDir>/<slug>/`, replacing any
 * previous contents atomically (staged in a temp dir, then swapped in) so
 * edge-runtime never sees a half-written function.
 */
export async function writeFunctionFiles(
  functionsDir: string,
  slug: string,
  files: FunctionFile[]
): Promise<void> {
  if (!isValidSlug(slug)) throw new Error(`invalid function slug: ${slug}`)
  if (files.length === 0) throw new Error('at least one file is required')

  const staging = await mkdtemp(path.join(functionsDir, `.deploy-${slug}-`))
  try {
    for (const file of files) {
      const target = assertSafeRelativePath(staging, file.name)
      await mkdir(path.dirname(target), { recursive: true })
      await writeFile(target, file.content, 'utf8')
    }
    const finalDir = path.join(functionsDir, slug)
    const backup = `${staging}.old`
    let hadPrevious = true
    try {
      await rename(finalDir, backup)
    } catch {
      hadPrevious = false
    }
    await rename(staging, finalDir)
    if (hadPrevious) await rm(backup, { recursive: true, force: true })
  } catch (err) {
    await rm(staging, { recursive: true, force: true })
    throw err
  }
}

export async function deleteFunctionFiles(functionsDir: string, slug: string): Promise<void> {
  if (!isValidSlug(slug)) throw new Error(`invalid function slug: ${slug}`)
  await rm(path.join(functionsDir, slug), { recursive: true, force: true })
}

const SECRETS_FILE = '.secrets.json'

/**
 * Persists function secrets as a JSON object in the shared functions volume.
 * The `main` edge function merges this file into each user worker's
 * environment, so changes apply without restarting edge-runtime.
 */
export async function writeSecretsFile(
  functionsDir: string,
  secrets: Record<string, string>
): Promise<void> {
  const target = path.join(functionsDir, SECRETS_FILE)
  const tmp = `${target}.tmp`
  await writeFile(tmp, `${JSON.stringify(secrets, null, 2)}\n`, 'utf8')
  await rename(tmp, target)
}

export async function readSecretsFile(functionsDir: string): Promise<Record<string, string>> {
  try {
    const raw = await readFile(path.join(functionsDir, SECRETS_FILE), 'utf8')
    const parsed: unknown = JSON.parse(raw)
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const out: Record<string, string> = {}
      for (const [key, value] of Object.entries(parsed)) {
        if (typeof value === 'string') out[key] = value
      }
      return out
    }
    return {}
  } catch {
    return {}
  }
}
