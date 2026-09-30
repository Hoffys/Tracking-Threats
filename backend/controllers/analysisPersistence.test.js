import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

test('public scans retain coverage and link scores without raw finding phrases', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'tracking-analysis-'))
  const filename = path.join(directory, 'test.sqlite')
  Object.assign(process.env, {
    DATABASE_URL: '', DATABASE_PATH: filename, PUBLIC_DEPLOYMENT: 'true', STORE_SCAN_CONTENT: 'false',
    SMTP_ENABLED: 'false', RESEND_API_KEY: '', REPUTATION_ENABLED: 'false',
  })
  const { dbPromise, initDatabase } = await import('../db/database.js')
  const db = await dbPromise
  try {
    await initDatabase()
    const { createEmailScan, createMessageScan } = await import('./scanController.js')
    const scan = await createEmailScan({ sender: 'person@example.org', subject: 'Hello',
      body: 'Share marker-private-123 password now. https://paypal.test/login' })
    assert.equal(scan.status, 'Dangerous')
    assert.equal(scan.coverage.status, 'unavailable')
    assert.ok(scan.emailBreakdown.links.score <= 50)
    assert.equal(scan.emailBreakdown.links.extracted, undefined)
    const saved = await db.get('SELECT details, content FROM scans WHERE id = ?', scan.id)
    assert.equal(saved.content, '')
    assert.equal(saved.details.includes('marker-private-123'), false)
    const evidence = await db.all('SELECT details FROM scan_evidence WHERE scan_id = ?', scan.id)
    assert.equal(JSON.stringify(evidence).includes('marker-private-123'), false)
    const categorized = await createMessageScan({ target: 'Discussion', content: 'A discussion of casino gambling and torrents.' })
    assert.equal(categorized.score, 100)
    assert.equal(categorized.categoryWarnings.length, 2)
    assert.ok(categorized.categoryWarnings.every((item) => typeof item === 'string'))
    assert.equal(categorized.coverage.status, 'local-only')
  } finally {
    await db.close()
    await fs.unlink(filename)
    await fs.rmdir(directory)
  }
})
