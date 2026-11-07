import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import test from 'node:test'

const source = readFileSync(new URL('./email-batch.js', import.meta.url), 'utf8')

function createEngine({ size = 10, rows = [], maxConcurrency = 4, providerId = 'unknown' } = {}) {
  let viewId = 'inbox'
  let enabled = true
  const callbacks = []
  const sent = []
  const states = []
  const sandbox = { globalThis: {} }
  vm.runInNewContext(source, sandbox)
  const engine = sandbox.globalThis.createEmailBatchEngine({
    providerId,
    getViewId: () => viewId,
    getRows: () => rows,
    extractRow: (row) => row,
    isEligible: (email) => Boolean(email.body && email.body.length >= 12),
    submit: (email, callback) => { sent.push(email.id); callbacks.push(callback) },
    getLevel: (scan) => scan.level ?? 'safe',
    isEnabled: () => enabled,
    initialBatchSize: size,
    maxConcurrency,
    onState: (state) => states.push(state),
  })
  return {
    engine, callbacks, sent, states,
    setRows: (nextRows) => { rows = nextRows },
    setView: (nextView) => { viewId = nextView },
    setEnabled: (nextEnabled) => { enabled = nextEnabled },
  }
}

const rows = (start, count) => Array.from({ length: count }, (_, index) => {
  const id = `message-${start + index}`
  return { id, email: { id, body: 'A sufficiently long synthetic email preview.' } }
})

function settleAll(callbacks, response = { level: 'safe' }) {
  while (callbacks.length) callbacks.shift()(null, response)
}

test('shared engine supports each existing batch size', () => {
  for (const size of [10, 20, 30, 40, 50]) {
    const harness = createEngine({ size, rows: rows(0, size) })
    harness.engine.scan()
    assert.equal(harness.callbacks.length, 4)
    assert.equal(harness.sent.length, 4)
    while (harness.engine.getState().attempts < size) {
      harness.callbacks.shift()(null, { level: 'safe' })
    }
    settleAll(harness.callbacks)
    assert.equal(harness.engine.getState().attempts, size)
    assert.equal(harness.engine.getState().stats.checked, size)
    assert.equal(harness.engine.getState().paused, true)
  }
})

test('repeated scans deduplicate stable IDs and newly rendered rows fill the same batch', () => {
  const harness = createEngine({ rows: rows(0, 3) })
  harness.engine.scan()
  harness.engine.scan()
  assert.deepEqual(harness.sent, ['message-0', 'message-1', 'message-2'])
  settleAll(harness.callbacks)
  harness.setRows(rows(0, 8))
  harness.engine.scan()
  settleAll(harness.callbacks)
  assert.deepEqual(harness.sent, rows(0, 8).map(({ id }) => id))
  assert.equal(harness.engine.getState().attempts, 8)
  assert.equal(harness.engine.getState().waitingForRows, true)
})

test('failed messages are retryable and successful retry clears failed count', () => {
  const harness = createEngine({ rows: rows(0, 2) })
  harness.engine.scan()
  harness.callbacks.shift()(new Error('temporary failure'))
  harness.callbacks.shift()(null, { level: 'safe' })
  assert.equal(harness.engine.getState().stats.failed, 1)
  assert.equal(harness.engine.retryFailed(), true)
  assert.equal(harness.sent.filter((id) => id === 'message-0').length, 2)
  harness.callbacks.shift()(null, { level: 'safe' })
  assert.equal(harness.engine.getState().stats.failed, 0)
  assert.equal(harness.engine.getState().stats.checked, 2)
})

test('view changes discard old progress and ignore late results from the previous folder', () => {
  const harness = createEngine({ rows: rows(0, 5) })
  harness.engine.scan()
  const pending = [...harness.callbacks]
  harness.setView('sent')
  assert.equal(harness.engine.handleViewChange(), true)
  assert.equal(harness.engine.getState().viewId, 'sent')
  assert.equal(harness.engine.getState().attempts, 0)
  pending[0](null, { level: 'dangerous' })
  assert.equal(harness.engine.getState().stats.checked, 0)
  assert.equal(harness.engine.getState().results.length, 0)
  harness.setRows(rows(10, 4))
  harness.engine.scan()
  assert.equal(harness.sent.length, 5)
  pending[1](null, { level: 'safe' })
  pending[2](null, { level: 'safe' })
  pending[3](null, { level: 'safe' })
  assert.equal(harness.sent.length, 8)
  assert.equal(harness.engine.getState().pending, 4)
})

test('consent withdrawal prevents queued submissions and malformed rows are ignored', () => {
  const malformed = [{ id: '', email: { body: 'A sufficiently long message.' } }, ...rows(0, 12)]
  const harness = createEngine({ rows: malformed })
  harness.engine.scan()
  assert.equal(harness.sent.length, 4)
  harness.setEnabled(false)
  harness.engine.cancel()
  settleAll(harness.callbacks)
  harness.engine.scan()
  assert.equal(harness.sent.length, 4)
  assert.ok(harness.sent.every(Boolean))
})

test('concurrency is capped at four even if an adapter requests more', () => {
  const harness = createEngine({ rows: rows(0, 20), maxConcurrency: 20 })
  harness.engine.scan()
  assert.equal(harness.callbacks.length, 4)
  harness.callbacks.shift()(null, { level: 'safe' })
  assert.equal(harness.callbacks.length, 4)
})

test('Gmail and Outlook batch results retain backend threat classification and evidence fields', () => {
  const classification = {
    threatName: 'Suspected phishing email',
    threatType: 'Phishing / credential theft',
    confidence: 'Medium',
    whyDetected: ['The message asks for account credentials through an unfamiliar link.'],
    evidenceSources: ['Email content rules', 'PhishTank'],
  }
  const coverage = { status: 'partial', checkedProviders: 1, totalProviders: 2, limitations: ['One reputation provider was unavailable.'] }

  for (const providerId of ['gmail', 'outlook-cloud']) {
    const harness = createEngine({ providerId, rows: rows(0, 1) })
    harness.engine.scan()
    harness.callbacks.shift()(null, {
      status: 'Dangerous',
      score: 18,
      coverage,
      categories: ['phishing-indicators'],
      categoryWarnings: [],
      ...classification,
    })

    const result = harness.engine.getState().results[0]
    assert.equal(result.threatName, classification.threatName)
    assert.equal(result.threatType, classification.threatType)
    assert.equal(result.confidence, classification.confidence)
    assert.deepEqual(result.whyDetected, classification.whyDetected)
    assert.deepEqual(result.evidenceSources, classification.evidenceSources)
    assert.deepEqual(result.coverage, coverage)
    assert.equal(result.score, 18)
  }
})

test('batch results tolerate missing optional classification fields and retain safe scan status', () => {
  const harness = createEngine({ providerId: 'outlook-cloud', rows: rows(0, 1) })
  harness.engine.scan()
  harness.callbacks.shift()(null, {
    status: 'Safe',
    score: 100,
    coverage: { status: 'local-only', checkedProviders: 0, totalProviders: 0, limitations: ['Reputation providers were not checked.'] },
    categories: [],
    categoryWarnings: [],
  })

  const result = harness.engine.getState().results[0]
  assert.equal(result.status, 'Safe')
  assert.equal(result.score, 100)
  assert.equal(result.threatName, undefined)
  assert.equal(result.whyDetected, undefined)
  assert.equal(result.evidenceSources, undefined)
})
