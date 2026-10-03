import assert from 'node:assert/strict'
import { Buffer } from 'node:buffer'
import test from 'node:test'
import {
  canInspectFileAsText,
  maxFileTextPreviewBytes,
  readFileTextPreview,
} from './fileInspection.js'

const namedBlob = (parts, name, type = '') => {
  const blob = new Blob(parts, { type })
  Object.defineProperty(blob, 'name', { value: name })
  return blob
}

test('binary executables use metadata and hash without a text preview', async () => {
  const file = namedBlob([new Uint8Array([0x4d, 0x5a, 0, 0xff])], 'setup.exe', 'application/x-msdownload')
  assert.equal(canInspectFileAsText(file), false)
  assert.equal(await readFileTextPreview(file), '')
})

test('text and script files retain a bounded content preview', async () => {
  const content = 'A'.repeat(maxFileTextPreviewBytes + 100)
  const textFile = namedBlob([content], 'notes.txt', 'application/octet-stream')
  assert.equal(canInspectFileAsText(textFile), true)
  assert.equal((await readFileTextPreview(textFile)).length, maxFileTextPreviewBytes)
})

test('worst-case escaped text preview remains below the backend JSON body limit', async () => {
  const textFile = namedBlob([new Uint8Array(maxFileTextPreviewBytes)], 'diagnostic.log', 'text/plain')
  const content = await readFileTextPreview(textFile)
  const requestBody = JSON.stringify({
    fileName: textFile.name,
    mimeType: textFile.type,
    size: textFile.size,
    content,
    sha256: 'a'.repeat(64),
  })
  assert.ok(Buffer.byteLength(requestBody) < 512 * 1024)
})
