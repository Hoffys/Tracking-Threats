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

test('client records require ownership and admin deletion is audited', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'tracking-threats-access-'))
  const port = await freePort()
  const adminToken = 'test-admin-token-with-sufficient-random-length'
  const child = spawn(process.execPath, ['backend/server.js'], {
    cwd: root,
    env: {
      ...process.env,
      PORT: String(port),
      PUBLIC_DEPLOYMENT: 'true',
      DATABASE_URL: '',
      DATABASE_PATH: path.join(directory, 'test.sqlite'),
      ADMIN_API_TOKEN: adminToken,
      STORE_SCAN_CONTENT: 'false',
      AUTO_MONITOR: 'false',
      SMTP_ENABLED: 'false',
      URLHAUS_AUTH_KEY: '',
      PHISHTANK_APP_KEY: '',
      VIRUSTOTAL_API_KEY: '',
      GOOGLE_SAFE_BROWSING_API_KEY: '',
      ABUSEIPDB_API_KEY: '',
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
        const health = await call('/health')
        if (health.status === 200) { ready = true; break }
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 100))
      }
    }
    assert.equal(ready, true, serverOutput)

    const first = await call('/public/clients', { method: 'POST' })
    const second = await call('/public/clients', { method: 'POST' })
    assert.equal(first.status, 201)
    assert.equal(second.status, 201)
    assert.notEqual(first.body.clientId, second.body.clientId)
    const credentialPath = `/public/clients/${first.body.clientId}`
    assert.equal((await call(credentialPath)).status, 401)
    assert.equal((await call(credentialPath, {
      headers: { 'X-Client-Token': first.body.token },
    })).status, 200)

    const activityPath = `/public/activity/${first.body.clientId}`
    assert.equal((await call(activityPath)).status, 401)
    assert.equal((await call(activityPath, {
      headers: { 'X-Client-Token': second.body.token },
    })).status, 403)
    assert.equal((await call(activityPath, {
      headers: { 'X-Client-Token': first.body.token },
    })).status, 200)
    const settingsPath = `/notification-settings?clientId=${first.body.clientId}`
    assert.equal((await call(settingsPath)).status, 401)
    assert.equal((await call(settingsPath, {
      headers: { 'X-Client-Token': second.body.token },
    })).status, 403)
    assert.equal((await call(settingsPath, {
      headers: { 'X-Client-Token': first.body.token },
    })).status, 200)

    const scan = {
      target: 'Example message',
      message: 'Hello from the access test',
      source: 'public-web-scan',
      clientId: first.body.clientId,
      privacyAccepted: true,
    }
    assert.equal((await call('/scan/message', {
      method: 'POST',
      body: JSON.stringify(scan),
    })).status, 401)
    assert.equal((await call('/scan/message', {
      method: 'POST',
      headers: { 'X-Client-Token': second.body.token },
      body: JSON.stringify(scan),
    })).status, 403)
    const saved = await call('/scan/message', {
      method: 'POST',
      headers: { 'X-Client-Token': first.body.token },
      body: JSON.stringify(scan),
    })
    assert.equal(saved.status, 201, JSON.stringify(saved.body))
    assert.equal((await call(activityPath, {
      headers: { 'X-Client-Token': first.body.token },
    })).body.scans.length, 1)

    assert.equal((await call(`/public/data/${first.body.clientId}`, {
      method: 'DELETE',
      headers: { 'X-Client-Token': second.body.token },
    })).status, 403)
    assert.equal((await call('/admin/overview')).status, 401)
    assert.equal((await call('/admin/overview', {
      headers: { Authorization: 'Bearer wrong-token' },
    })).status, 403)
    const adminHeaders = { Authorization: `Bearer ${adminToken}` }
    const overview = await call('/admin/overview', { headers: adminHeaders })
    assert.equal(overview.status, 200)
    assert.equal(overview.body.clients, 2)
    const detail = await call(`/admin/clients/${first.body.clientId}`, {
      headers: adminHeaders,
    })
    assert.equal(detail.status, 200)
    assert.equal(detail.body.recent.length, 1)
    assert.equal(JSON.stringify(detail.body).includes(scan.message), false)

    const deletePath = `/admin/clients/${first.body.clientId}/data`
    assert.equal((await call(deletePath, {
      method: 'DELETE',
      headers: adminHeaders,
      body: JSON.stringify({ confirmClientId: 'wrong', verifiedRequest: true }),
    })).status, 400)
    const deleted = await call(deletePath, {
      method: 'DELETE',
      headers: adminHeaders,
      body: JSON.stringify({ confirmClientId: first.body.clientId, verifiedRequest: true }),
    })
    assert.equal(deleted.status, 200)
    assert.equal(deleted.body.deletedScans, 1)
    const rejectedCredential = await call(credentialPath, {
      headers: { 'X-Client-Token': first.body.token },
    })
    assert.equal(rejectedCredential.status, 403)
    assert.equal(rejectedCredential.body.code, 'CLIENT_ACCESS_DENIED')
    const replacement = await call('/public/clients', { method: 'POST' })
    assert.notEqual(replacement.body.clientId, first.body.clientId)
    assert.equal((await call(`/public/activity/${replacement.body.clientId}`, {
      headers: { 'X-Client-Token': replacement.body.token },
    })).body.scans.length, 0)
    assert.equal((await call('/scan/message', {
      method: 'POST',
      headers: { 'X-Client-Token': replacement.body.token },
      body: JSON.stringify({ ...scan, clientId: replacement.body.clientId }),
    })).status, 201)
    assert.equal((await call(activityPath, {
      headers: { 'X-Client-Token': first.body.token },
    })).status, 403)
    const logs = await call('/admin/logs', { headers: adminHeaders })
    assert.equal(logs.body.actions[0].action, 'client-data-deletion')
    assert.equal(logs.body.actions[0].deleted_scans, 1)
    assert.equal((await call(`/public/data/${second.body.clientId}`, {
      method: 'DELETE',
      headers: { 'X-Client-Token': second.body.token },
    })).status, 200)
    assert.equal((await call(`/public/activity/${second.body.clientId}`, {
      headers: { 'X-Client-Token': second.body.token },
    })).status, 403)
  } finally {
    child.kill()
    if (child.exitCode === null) await once(child, 'exit')
    await fs.rm(directory, { recursive: true, force: true })
  }
})
