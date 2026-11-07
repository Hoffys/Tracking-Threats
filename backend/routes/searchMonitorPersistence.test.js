import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import fs from 'node:fs/promises'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')

const freePort = async () => {
  const server = net.createServer()
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = server.address().port
  server.close()
  await once(server, 'close')
  return port
}

test('extension URL and email scans persist to client activity while search previews remain non-persistent', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'tracking-threats-search-monitor-'))
  const port = await freePort()
  const child = spawn(process.execPath, ['backend/server.js'], {
    cwd: root,
    env: {
      ...process.env,
      PORT: String(port),
      PUBLIC_DEPLOYMENT: 'true',
      DATABASE_URL: '',
      DATABASE_PATH: path.join(directory, 'test.sqlite'),
      REPUTATION_ENABLED: 'false',
      PAGE_INSPECTION_ENABLED: 'false',
      SMTP_ENABLED: 'false',
      RESEND_API_KEY: '',
      AUTO_MONITOR: 'false',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let serverOutput = ''
  child.stdout.on('data', (chunk) => { serverOutput += chunk.toString() })
  child.stderr.on('data', (chunk) => { serverOutput += chunk.toString() })

  const call = async (pathName, options = {}) => {
    const response = await fetch(`http://127.0.0.1:${port}/api${pathName}`, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...options.headers },
    })
    return { status: response.status, body: await response.json() }
  }

  try {
    let ready = false
    for (let attempt = 0; attempt < 600; attempt += 1) {
      if (child.exitCode !== null) break
      try {
        if ((await call('/health')).status === 200) { ready = true; break }
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 100))
      }
    }
    assert.equal(ready, true, serverOutput)

    const registration = await call('/public/clients', { method: 'POST' })
    assert.equal(registration.status, 201, JSON.stringify(registration.body))
    const headers = { 'X-Client-Token': registration.body.token }

    const automaticNavigation = await call('/scan/url', {
      method: 'POST', headers,
      body: JSON.stringify({
        url: 'https://automatic-navigation.example/path',
        source: 'browser-extension',
        preview: false,
        clientId: registration.body.clientId,
      }),
    })
    assert.equal(automaticNavigation.status, 201, JSON.stringify(automaticNavigation.body))
    assert.equal(automaticNavigation.body.source, 'browser-extension')

    const manualExtensionScan = await call('/scan/url', {
      method: 'POST', headers,
      body: JSON.stringify({
        url: 'https://manual-extension.example/path',
        source: 'browser-extension',
        preview: false,
        clientId: registration.body.clientId,
      }),
    })
    assert.equal(manualExtensionScan.status, 201, JSON.stringify(manualExtensionScan.body))

    const noConsent = await call('/scan/url', {
      method: 'POST', headers,
      body: JSON.stringify({
        url: 'https://no-consent.example/path',
        source: 'browser-search-monitor',
        preview: false,
        clientId: registration.body.clientId,
      }),
    })
    assert.equal(noConsent.status, 400)

    const staleConsent = await call('/scan/url', {
      method: 'POST', headers,
      body: JSON.stringify({
        url: 'https://stale-consent.example/path',
        source: 'browser-search-monitor',
        preview: false,
        clientId: registration.body.clientId,
        privacyAccepted: true,
        privacyNoticeVersion: '2026.09',
      }),
    })
    assert.equal(staleConsent.status, 400)

    const persisted = await call('/scan/url', {
      method: 'POST', headers,
      body: JSON.stringify({
        url: 'https://search-result.example/path',
        source: 'browser-search-monitor',
        reason: 'search-result-preview',
        preview: false,
        clientId: registration.body.clientId,
        privacyAccepted: true,
        privacyNoticeVersion: '2026.10',
      }),
    })
    assert.equal(persisted.status, 201, JSON.stringify(persisted.body))
    assert.ok(persisted.body.id)
    assert.equal(persisted.body.source, 'browser-search-monitor')

    const gmailBatch = await call('/scan/email', {
      method: 'POST', headers,
      body: JSON.stringify({
        sender: 'sender@example.test',
        subject: 'Gmail batch fixture',
        body: 'Synthetic Gmail batch scan content for persistence verification.',
        source: 'browser-email-monitor',
        clientId: registration.body.clientId,
        privacyAccepted: true,
        privacyNoticeVersion: '2026.12',
      }),
    })
    assert.equal(gmailBatch.status, 201, JSON.stringify(gmailBatch.body))
    assert.equal(gmailBatch.body.type, 'Email')
    assert.equal(gmailBatch.body.source, 'browser-email-monitor')

    const outlookBatch = await call('/scan/email', {
      method: 'POST', headers,
      body: JSON.stringify({
        sender: 'sender@example.test',
        subject: 'Outlook Cloud batch fixture',
        body: 'Synthetic Outlook Cloud batch scan content for persistence verification.',
        source: 'browser-email-monitor',
        clientId: registration.body.clientId,
        privacyAccepted: true,
        privacyNoticeVersion: '2026.12',
      }),
    })
    assert.equal(outlookBatch.status, 201, JSON.stringify(outlookBatch.body))
    assert.equal(outlookBatch.body.type, 'Email')
    assert.equal(outlookBatch.body.source, 'browser-email-monitor')

    const preview = await call('/scan/url', {
      method: 'POST', headers,
      body: JSON.stringify({
        url: 'https://preview-only.example/path',
        source: 'browser-search-preview',
        preview: true,
        clientId: registration.body.clientId,
      }),
    })
    assert.equal(preview.status, 200, JSON.stringify(preview.body))
    assert.equal(preview.body.id, undefined)

    const activity = await call(`/public/activity/${registration.body.clientId}`, { headers })
    assert.equal(activity.status, 200, JSON.stringify(activity.body))
    assert.equal(activity.body.scans.length, 5)
    assert.deepEqual(new Set(activity.body.scans.map((scan) => scan.id)), new Set([
      automaticNavigation.body.id,
      manualExtensionScan.body.id,
      persisted.body.id,
      gmailBatch.body.id,
      outlookBatch.body.id,
    ]))
    assert.equal(activity.body.liveFeed.length, 5)
    assert.equal(activity.body.stats.total, 5)
    assert.equal(activity.body.stats.liveScanCount, 5)
    assert.equal(activity.body.scans.some((scan) => scan.source === 'browser-search-preview'), false)
    assert.equal(activity.body.scans.find((scan) => scan.id === persisted.body.id)?.source, 'browser-search-monitor')
    assert.equal(activity.body.scans.every((scan) => scan.clientId === registration.body.clientId), true)
  } finally {
    if (child.exitCode === null) {
      const exited = once(child, 'exit')
      child.kill()
      await exited
    }
    await fs.rm(directory, { recursive: true, force: true })
  }
})
