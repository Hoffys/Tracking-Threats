import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'

const source = readFileSync(new URL('./background.js', import.meta.url), 'utf8')
const download = { id: 1, url: 'https://example.com/file.exe' }
const safe = { status: 'Safe', score: 100 }
const dangerous = { status: 'Dangerous', score: 20, blocked: true }

function monitor(urlScan, fileScan) {
  const cancelled = []
  const statuses = []
  let fileScans = 0
  const events = []
  const sandbox = {
    chrome: { downloads: { pause: async () => { events.push('pause') }, resume: async () => { events.push('resume') } } },
    getClientId: async () => { events.push('credential'); return 'test-client' },
    scanDownloadUrl: async () => urlScan,
    scanDownloadFile: async () => { fileScans += 1; return fileScan() },
    cancelDangerousDownload: async (item, scan) => { cancelled.push({ item, scan }); events.push('cancel'); return true },
    saveStatus: async (status) => { statuses.push(status) },
    getDownloadFileName: () => 'file.exe',
  }
  const blockedCheck = source.slice(source.indexOf('function isBlockedScan('), source.indexOf('\n}', source.indexOf('function isBlockedScan(')) + 2)
  const downloadScan = source.slice(source.indexOf('async function scanDownload(downloadItem)'), source.indexOf('async function handleTabUrl'))
  vm.runInNewContext(`${blockedCheck}\n${downloadScan}`, sandbox)
  return { scan: () => sandbox.scanDownload(download), cancelled, statuses, events, fileScans: () => fileScans }
}

test('a dangerous download URL is cancelled before a failing file lookup', async () => {
  const app = monitor(dangerous, () => { throw new Error('File API unavailable') })
  assert.equal(await app.scan(), dangerous)
  assert.equal(app.fileScans(), 0)
  assert.deepEqual(app.cancelled, [{ item: download, scan: dangerous }])
  assert.deepEqual(app.events, ['pause', 'credential', 'cancel'])
})

test('file detection still cancels downloads with a safe or unscannable URL', async () => {
  for (const urlScan of [safe, null]) {
    const app = monitor(urlScan, () => dangerous)
    assert.equal(await app.scan(), dangerous)
    assert.equal(app.fileScans(), 1)
    assert.deepEqual(app.cancelled, [{ item: download, scan: dangerous }])
  }
})

test('safe downloads remain allowed and lookup failures are reported', async () => {
  const app = monitor(safe, () => safe)
  assert.equal(await app.scan(), safe)
  assert.equal(app.cancelled.length, 0)
  assert.equal(app.statuses[0].lastStatus, 'Safe')
  assert.deepEqual(app.events, ['pause', 'credential', 'resume'])

  const failed = monitor(safe, () => { throw new Error('File API unavailable') })
  const result = await failed.scan()
  assert.equal(result.ok, false)
  assert.equal(result.error, 'File API unavailable')
  assert.equal(failed.statuses[0].ok, false)
  assert.deepEqual(failed.events, ['pause', 'credential', 'resume'])
})

test('failed browser cancellation does not claim the download was blocked', async () => {
  const statuses = []
  const sandbox = {
    chrome: { downloads: { cancel: async () => { throw new Error('Already complete') } } },
    saveStatus: async (value) => statuses.push(value),
    getDownloadFileName: () => 'file.exe', notifyScanResult: async () => {},
  }
  vm.runInNewContext(source.slice(source.indexOf('async function cancelDangerousDownload('), source.indexOf('async function scanDownload(downloadItem)')), sandbox)
  assert.equal(await sandbox.cancelDangerousDownload(download, dangerous), false)
  assert.equal(statuses[0].lastStatus, 'Dangerous')
  assert.match(statuses[0].downloadWarning, /could not cancel/)
})
