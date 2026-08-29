import assert from 'node:assert/strict'
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, it } from 'node:test'

import {
  deleteFunctionFiles,
  isValidSlug,
  readSecretsFile,
  writeFunctionFiles,
  writeSecretsFile,
} from '../src/functions.js'

describe('isValidSlug', () => {
  it('accepts simple slugs', () => {
    assert.equal(isValidSlug('hello'), true)
    assert.equal(isValidSlug('my-function_2'), true)
  })

  it('rejects the reserved main service and unsafe names', () => {
    assert.equal(isValidSlug('main'), false)
    assert.equal(isValidSlug(''), false)
    assert.equal(isValidSlug('../evil'), false)
    assert.equal(isValidSlug('a/b'), false)
    assert.equal(isValidSlug('a b'), false)
  })
})

describe('function files', () => {
  let dir: string

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'fn-test-'))
  })

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  it('writes files under the function directory', async () => {
    await writeFunctionFiles(dir, 'hello', [
      { name: 'index.ts', content: 'export default 1' },
      { name: 'lib/util.ts', content: 'export const x = 2' },
    ])

    assert.equal(await readFile(path.join(dir, 'hello/index.ts'), 'utf8'), 'export default 1')
    assert.equal(await readFile(path.join(dir, 'hello/lib/util.ts'), 'utf8'), 'export const x = 2')
  })

  it('replaces previous contents completely', async () => {
    await writeFunctionFiles(dir, 'hello', [{ name: 'old.ts', content: 'old' }])
    await writeFunctionFiles(dir, 'hello', [{ name: 'index.ts', content: 'new' }])

    const entries = await readdir(path.join(dir, 'hello'))
    assert.deepEqual(entries.sort(), ['index.ts'])
  })

  it('rejects path traversal in file names', async () => {
    await assert.rejects(
      writeFunctionFiles(dir, 'hello', [{ name: '../outside.ts', content: 'nope' }]),
      /invalid file path/
    )
    const entries = await readdir(dir)
    assert.equal(entries.some((entry) => entry === 'outside.ts'), false)
  })

  it('rejects invalid slugs', async () => {
    await assert.rejects(
      writeFunctionFiles(dir, '../evil', [{ name: 'index.ts', content: 'x' }]),
      /invalid function slug/
    )
    await assert.rejects(writeFunctionFiles(dir, 'main', [{ name: 'index.ts', content: 'x' }]))
  })

  it('deletes function directories', async () => {
    await writeFunctionFiles(dir, 'hello', [{ name: 'index.ts', content: 'x' }])
    await deleteFunctionFiles(dir, 'hello')
    const entries = await readdir(dir)
    assert.deepEqual(entries, [])
  })
})

describe('secrets file', () => {
  let dir: string

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'secrets-test-'))
  })

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  it('round-trips secrets', async () => {
    await writeSecretsFile(dir, { MY_KEY: 'value', OTHER: 'x' })
    assert.deepEqual(await readSecretsFile(dir), { MY_KEY: 'value', OTHER: 'x' })
  })

  it('returns an empty object when the file is missing or invalid', async () => {
    assert.deepEqual(await readSecretsFile(dir), {})
  })
})
