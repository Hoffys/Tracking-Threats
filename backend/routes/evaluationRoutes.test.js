import assert from 'node:assert/strict'
import test from 'node:test'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdtemp } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import net from 'node:net'
import { fileURLToPath } from 'node:url'
import { open } from 'sqlite'
import sqlite3 from 'sqlite3'

const server = fileURLToPath(new URL('../server.js', import.meta.url))
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

test('evaluation API protects reports, stores real metrics across restart, and denies stale credentials before purge', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'tracking-audit-api-'))
  const socket = net.createServer().listen(0, '127.0.0.1')
  await once(socket, 'listening')
  const port = socket.address().port
  await new Promise((resolve) => socket.close(resolve))
  const token = 'audit-test-admin-token'
  const filename = path.join(directory, 'test.sqlite')
  let child, output = ''
  const call = async (route, options = {}) => {
    const response = await fetch(`http://127.0.0.1:${port}/api${route}`, { ...options, headers: { 'Content-Type': 'application/json', ...options.headers } })
    return { status: response.status, body: await response.json() }
  }
  const start = async () => {
    child = spawn(process.execPath, [server], { cwd: directory, env: { ...process.env, PORT: String(port), DATABASE_URL: '', DATABASE_PATH: filename, ADMIN_API_TOKEN: token, PUBLIC_DEPLOYMENT: 'true', REPUTATION_ENABLED: 'false', SMTP_ENABLED: 'false', AUTO_MONITOR: 'false', RESEND_API_KEY: '' }, stdio: ['ignore', 'pipe', 'pipe'] })
    child.stdout.on('data', (chunk) => { output += chunk })
    child.stderr.on('data', (chunk) => { output += chunk })
    for (let attempt = 0; attempt < 150; attempt++) {
      if (child.exitCode !== null) throw new Error(output)
      try { if ((await call('/health')).status === 200) return } catch { /* starting */ }
      await delay(50)
    }
    throw new Error(`Server did not start: ${output}`)
  }
  const stop = async () => { if (child?.exitCode === null) { const stopped = once(child, 'exit'); child.kill(); await stopped } }
  const headers = { Authorization: `Bearer ${token}` }
  try {
    await start()
    assert.equal((await call('/admin/evaluations')).status, 401)
    assert.equal((await call('/admin/evaluations', { headers: { Authorization: 'Bearer wrong' } })).status, 403)
    assert.equal((await call('/admin/evaluations', { headers })).status, 200)
    assert.equal((await call('/admin/evaluations', { method: 'POST', headers, body: JSON.stringify({ dataset: '../secret' }) })).status, 400)
    const created = await call('/admin/evaluations', { method: 'POST', headers, body: JSON.stringify({ dataset: 'synthetic', mode: 'production', limit: 4 }) })
    assert.equal(created.status, 202)
    let completed
    for (let i = 0; i < 100; i++) {
      completed = await call(`/admin/evaluations/${created.body.id}`, { headers })
      if (completed.body.status !== 'running') break
      await delay(50)
    }
    assert.equal(completed.body.status, 'completed', JSON.stringify(completed.body))
    assert.equal(completed.body.report.sample.evaluated, 4)
    assert.equal(completed.body.report.sample.failed, 0)
    const counts = completed.body.report.metrics.overall.warning
    assert.equal(counts.tp + counts.tn + counts.fp + counts.fn, 4)
    const connection = await open({ filename, driver: sqlite3.Database })
    try {
      assert.equal((await connection.get('SELECT COUNT(*) AS n FROM scans')).n, 0, 'evaluation must not pollute scan history')
      const credential = (await call('/public/clients', { method: 'POST' })).body
      await connection.run('UPDATE client_credentials SET created_at = ?, last_seen_at = ?, extension_seen_at = NULL WHERE client_id = ?', '2000-01-01T00:00:00.000Z', '2000-01-01T00:00:00.000Z', credential.clientId)
      const expired = await call(`/public/clients/${credential.clientId}`, { headers: { 'X-Client-Token': credential.token } })
      assert.equal(expired.status, 403)
      assert.equal(expired.body.code, 'CLIENT_ACCESS_DENIED')
      assert.equal((await connection.get('SELECT last_seen_at FROM client_credentials WHERE client_id = ?', credential.clientId)).last_seen_at, '2000-01-01T00:00:00.000Z')
      await connection.run('INSERT INTO evaluation_runs (id, dataset, mode, status, processed, total, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)', 'interrupted-fixture', 'synthetic', 'local', 'running', 1, 60, '2000-01-01T00:00:00.000Z')
    } finally { await connection.close() }
    await stop()
    await start()
    const restored = await call(`/admin/evaluations/${created.body.id}`, { headers })
    assert.deepEqual(restored.body.report, completed.body.report)
    assert.equal((await call('/admin/evaluations/interrupted-fixture', { headers })).body.status, 'interrupted')
    assert.equal((await call('/admin/evaluations', { headers })).body.history[0].id, created.body.id)
  } finally { await stop() }
})
