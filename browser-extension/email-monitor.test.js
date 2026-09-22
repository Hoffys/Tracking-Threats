import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import vm from 'node:vm'
import test from 'node:test'

const source = readFileSync(new URL('./email-monitor.js', import.meta.url), 'utf8')

function createMonitor() {
  const callbacks = []
  const sandbox = {
    TRACKING_THREATS_CONFIG: { APP_URL: 'https://tracking-threats.example/' },
    chrome: {
      storage: { local: { get: () => new Promise(() => {}) } },
      runtime: {
        lastError: null,
        sendMessage: (_message, callback) => callbacks.push(callback),
      },
    },
    document: { getElementById: () => null },
    window: { location: { hostname: 'mail.google.com' }, clearTimeout: () => {} },
  }
  vm.runInNewContext(`${source}
    let visibleRows = []
    let reviewPrompts = 0
    emailConsentGranted = true
    getGmailInboxRows = () => visibleRows
    getGmailInboxEmail = (row) => row.email
    getGmailInboxRowKey = (row) => row.id
    markGmailInboxRow = () => {}
    showInboxRiskWarning = () => {}
    showInboxStatus = () => {}
    showInboxReview = () => { reviewPrompts += 1 }
    clearEmailMonitorUi = () => {}
    globalThis.monitor = {
      setRows: (rows) => { visibleRows = rows },
      scan: scanGmailInbox,
      continueBatch: continueInboxBatch,
      stop: stopEmailMonitoring,
      state: () => ({
        consentGranted: emailConsentGranted,
        attempts: inboxAttempts,
        pending: inboxPending,
        paused: inboxPaused,
        waiting: inboxWaitingForRows,
        checked: inboxStats.checked,
        failed: inboxStats.failed,
        results: inboxResults,
        reviewPrompts,
      }),
    }
  `, sandbox, { filename: fileURLToPath(new URL('./email-monitor.js', import.meta.url)) })
  return { monitor: sandbox.monitor, callbacks }
}

const rows = (start, count) => Array.from({ length: count }, (_, offset) => ({
  id: `thread-${start + offset}`,
  dataset: {},
  email: {
    sender: `sender${start + offset}@example.com`,
    subject: `Message ${start + offset}`,
    body: 'Private preview text that must not enter the review list',
  },
}))

test('Gmail inbox pauses after 50 attempts and requires a choice for the next 50', () => {
  const { monitor, callbacks } = createMonitor()
  monitor.setRows(rows(0, 50))
  monitor.scan()
  assert.equal(callbacks.length, 4)

  for (let index = 0; index < 50; index += 1) {
    assert.ok(callbacks.length <= 4)
    callbacks.shift()({ ok: true, scan: { status: 'Safe', score: 100 } })
  }
  assert.equal(callbacks.length, 0)
  assert.equal(monitor.state().attempts, 50)
  assert.equal(monitor.state().checked, 50)
  assert.equal(monitor.state().paused, true)
  assert.equal(monitor.state().reviewPrompts, 1)
  assert.equal(monitor.state().results.length, 50)
  assert.equal('body' in monitor.state().results[0], false)

  monitor.setRows(rows(50, 50))
  monitor.scan()
  assert.equal(callbacks.length, 0)

  monitor.continueBatch()
  assert.equal(callbacks.length, 4)
  for (let index = 0; index < 50; index += 1) {
    callbacks.shift()({ ok: true, scan: { status: 'Safe', score: 100 } })
  }
  assert.equal(monitor.state().attempts, 100)
  assert.equal(monitor.state().paused, true)
  assert.equal(monitor.state().reviewPrompts, 2)
})

test('failed scans are reported and continuing waits for a new Gmail page', () => {
  const { monitor, callbacks } = createMonitor()
  monitor.setRows(rows(0, 50))
  monitor.scan()
  callbacks.shift()({ ok: false, error: 'Temporary failure' })
  for (let index = 1; index < 50; index += 1) {
    callbacks.shift()({ ok: true, scan: { status: 'Safe', score: 100 } })
  }
  assert.equal(monitor.state().failed, 1)
  assert.equal(monitor.state().checked, 49)
  assert.equal(monitor.state().paused, true)

  monitor.continueBatch()
  assert.equal(callbacks.length, 0)
  assert.equal(monitor.state().waiting, true)
  monitor.setRows(rows(50, 50))
  monitor.scan()
  assert.equal(callbacks.length, 4)
})

test('withdrawn consent ignores responses already in flight', () => {
  const { monitor, callbacks } = createMonitor()
  monitor.setRows(rows(0, 50))
  monitor.scan()
  assert.equal(callbacks.length, 4)

  monitor.stop()
  callbacks.shift()({ ok: true, scan: { status: 'Safe', score: 100 } })
  assert.equal(monitor.state().consentGranted, false)
  assert.equal(monitor.state().checked, 0)
  assert.equal(monitor.state().results.length, 0)
  monitor.scan()
  assert.equal(callbacks.length, 3)
})
