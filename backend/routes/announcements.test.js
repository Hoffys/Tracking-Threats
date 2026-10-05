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

test('staff announcements are authenticated and public updates are version aware', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'tracking-threats-announcements-'))
  const port = await freePort()
  const adminToken = 'announcement-test-admin-token'
  const child = spawn(process.execPath, ['backend/server.js'], {
    cwd: root,
    env: {
      ...process.env,
      PORT: String(port),
      PUBLIC_DEPLOYMENT: 'true',
      DATABASE_URL: '',
      DATABASE_PATH: path.join(directory, 'test.sqlite'),
      ADMIN_API_TOKEN: adminToken,
      AUTO_MONITOR: 'false',
      SMTP_ENABLED: 'false',
      RESEND_API_KEY: '',
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

    const adminHeaders = { Authorization: `Bearer ${adminToken}` }
    assert.equal((await call('/public/announcements?version=1.0.34')).status, 200)
    assert.equal((await call('/admin/announcements')).status, 401)

    const update = await call('/admin/announcements', {
      method: 'POST',
      headers: adminHeaders,
      body: JSON.stringify({
        type: 'update',
        title: 'Extension v1.0.35 available',
        message: 'Install the latest security and monitoring improvements.',
        priority: 'important',
        targetVersion: '1.0.35',
        expiresAt: null,
        isActive: true,
      }),
    })
    assert.equal(update.status, 201, JSON.stringify(update.body))
    assert.equal(update.body.isActive, true)

    const outdated = await call('/public/announcements?version=1.0.34')
    assert.equal(outdated.body.updateAvailable, true)
    assert.equal(outdated.body.latestVersion, '1.0.35')
    assert.equal(outdated.body.announcements[0].id, update.body.id)
    const current = await call('/public/announcements?version=1.0.35')
    assert.equal(current.body.updateAvailable, false)
    assert.deepEqual(current.body.announcements, [])

    const unpublished = await call(`/admin/announcements/${update.body.id}`, {
      method: 'PATCH',
      headers: adminHeaders,
      body: JSON.stringify({ isActive: false }),
    })
    assert.equal(unpublished.status, 200)
    assert.equal(unpublished.body.isActive, false)
    assert.deepEqual((await call('/public/announcements?version=1.0.34')).body.announcements, [])
    assert.equal((await call('/admin/announcements', { headers: adminHeaders })).body.length, 1)

    assert.equal((await call(`/admin/announcements/${update.body.id}`, { method: 'DELETE' })).status, 401)
    const deleted = await call(`/admin/announcements/${update.body.id}`, {
      method: 'DELETE',
      headers: adminHeaders,
    })
    assert.equal(deleted.status, 200)
    assert.deepEqual(deleted.body, { ok: true, id: update.body.id })
    assert.deepEqual((await call('/admin/announcements', { headers: adminHeaders })).body, [])
    assert.equal((await call(`/admin/announcements/${update.body.id}`, {
      method: 'DELETE',
      headers: adminHeaders,
    })).status, 404)
  } finally {
    child.kill()
    if (child.exitCode === null) await once(child, 'exit')
    await fs.rm(directory, { recursive: true, force: true })
  }
})
