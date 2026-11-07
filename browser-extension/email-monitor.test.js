import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import vm from 'node:vm'
import test from 'node:test'

const source = readFileSync(new URL('./email-monitor.js', import.meta.url), 'utf8')
const batchSource = readFileSync(new URL('./email-batch.js', import.meta.url), 'utf8')
const outlookBatchSource = readFileSync(new URL('./outlook-cloud-batch.js', import.meta.url), 'utf8')
const configSource = readFileSync(new URL('./config.js', import.meta.url), 'utf8')
const backgroundSource = readFileSync(new URL('./background.js', import.meta.url), 'utf8')
const popupSource = readFileSync(new URL('./popup.js', import.meta.url), 'utf8')
const manifest = JSON.parse(readFileSync(new URL('./manifest.json', import.meta.url), 'utf8'))

function outlookTreeItem(folderName, selected = true, title = folderName) {
  const attributes = {
    role: 'treeitem',
    'aria-selected': selected ? 'true' : 'false',
    'data-folder-name': folderName,
    title,
  }
  return { getAttribute: (name) => attributes[name] ?? null }
}

function outlookMessageList(label = 'Message list No conversations selected') {
  return { getAttribute: (name) => name === 'aria-label' ? label : name === 'role' ? 'listbox' : null }
}

function createMonitor({ hostname = 'mail.google.com', selectorMap = {}, hash = '#inbox', pathname: initialPathname = '/mail/inbox/id/account' } = {}) {
  const callbacks = []
  const messages = []
  const observerCallbacks = []
  const scheduledTimers = new Map()
  const intervalTimers = new Map()
  const warningScans = []
  const renderedTexts = []
  let nextTimerId = 0
  let pathname = initialPathname
  let treeItems = []
  let messageLists = []
  const sandbox = {
    intervalTimers,
    renderedTexts,
    setPathname: (nextPathname) => { pathname = nextPathname },
    setTreeItems: (items) => { treeItems = items },
    setMessageLists: (lists) => { messageLists = lists },
    chrome: {
      storage: { local: { get: () => new Promise(() => {}) } },
      runtime: {
        lastError: null,
        sendMessage: (message, callback) => { messages.push(message); callbacks.push(callback) },
        onMessage: { addListener: () => {} },
      },
    },
    document: {
      body: {},
      addEventListener: () => {},
      getElementById: () => null,
      createElement: (tag) => ({
        tag,
        style: {},
        children: [],
        set textContent(value) { renderedTexts.push(String(value)) },
        append(...children) { this.children.push(...children) },
        appendChild(child) { this.children.push(child) },
      }),
      querySelectorAll: (selector) => {
        if (selector === '[role="treeitem"][aria-selected="true"][data-folder-name]') {
          return treeItems.filter((item) => item.getAttribute('role') === 'treeitem' &&
            item.getAttribute('aria-selected') === 'true' && item.getAttribute('data-folder-name') !== null)
        }
        if (selector === '[role="listbox"]') return messageLists.length ? messageLists : selectorMap[selector] ?? []
        return selectorMap[selector] ?? []
      },
    },
    window: {
      location: { hostname, get pathname() { return pathname }, get hash() { return hash } },
      clearTimeout: (id) => scheduledTimers.delete(id),
      setTimeout: (callback, delay) => {
        const id = ++nextTimerId
        scheduledTimers.set(id, { callback, delay })
        return id
      },
      setInterval: (callback, delay) => {
        const id = ++nextTimerId
        intervalTimers.set(id, { callback, delay })
        return id
      },
      clearInterval: (id) => intervalTimers.delete(id),
      addEventListener: () => {},
      removeEventListener: () => {},
    },
    MutationObserver: class {
      constructor(callback) { this.callback = callback; observerCallbacks.push(callback) }
      observe() {}
      disconnect() {}
    },
    warningScans,
    setHash: (nextHash) => { hash = nextHash },
    setPathname: (nextPathname) => { pathname = nextPathname },
  }
  vm.runInNewContext(`${configSource}
    ${batchSource}
    ${outlookBatchSource}
    ${source}
    let visibleRows = []
    let reviewPrompts = 0
    let failurePrompts = 0
    let inboxStatusRefreshes = 0
    emailConsentGranted = true
    getGmailInboxRows = () => visibleRows
    getGmailInboxEmail = (row) => row.email
    getGmailInboxRowKey = (row) => row.id
    markGmailInboxRow = () => {}
    showInboxRiskWarning = () => {}
    showInboxStatus = () => { inboxStatusRefreshes += 1 }
    showInboxReview = () => { reviewPrompts += 1 }
    showEmailWarning = (scan) => warningScans.push(scan)
    showEmailScanFailure = () => { failurePrompts += 1 }
    clearEmailMonitorUi = () => {}
    globalThis.monitor = {
      setRows: (rows) => { visibleRows = rows },
      setHash: (nextHash) => globalThis.setHash(nextHash),
      setPathname: (nextPathname) => globalThis.setPathname(nextPathname),
      setTreeItems: (items) => globalThis.setTreeItems(items),
      setMessageLists: (lists) => globalThis.setMessageLists(lists),
      tickRouteMonitor: () => { for (const timer of intervalTimers.values()) timer.callback() },
      routeMonitorCount: () => intervalTimers.size,
      setBatchSize: (size) => setInboxBatchSize(size, false),
      scan: scanGmailInbox,
      scanOpened: scanOpenedEmail,
      getOpenedEmail,
      extractOutlookBatchMessage: extractOutlookCloudBatchMessage,
      outlookFolderId: getOutlookCloudFolderId,
      outlookAvailability: getOutlookCloudBatchAvailability,
      refreshOutlookRoute: refreshOutlookCloudRouteIfChanged,
      start: startEmailMonitoring,
      continueBatch: continueInboxBatch,
      stop: stopEmailMonitoring,
      getScanLevel,
      getStatusLabel,
      renderScanContext: appendScanContext,
      clearRenderedTexts: () => { renderedTexts.length = 0 },
      renderedTexts: () => [...renderedTexts],
      state: () => ({
        consentGranted: emailConsentGranted,
        attempts: inboxAttempts,
        pending: inboxPending,
        paused: inboxPaused,
        waiting: inboxWaitingForRows,
        checked: inboxStats.checked,
        failed: inboxStats.failed,
        results: inboxResults,
        viewId: gmailInboxViewId,
        reviewPrompts,
        failurePrompts,
        batchSize: inboxBatchSize,
        inboxStatusRefreshes,
      }),
    }
  `, sandbox, { filename: fileURLToPath(new URL('./email-monitor.js', import.meta.url)) })
  return {
    monitor: sandbox.monitor,
    callbacks,
    messages,
    observerCallbacks,
    warningScans,
    tickRouteMonitor: () => sandbox.monitor.tickRouteMonitor(),
    intervalCount: () => sandbox.monitor.routeMonitorCount(),
    flushTimers(delay) {
      const due = Array.from(scheduledTimers.entries()).filter(([, timer]) => timer.delay === delay)
      due.forEach(([id, timer]) => { scheduledTimers.delete(id); timer.callback() })
    },
  }
}

function createConsentLifecycle({ hostname = 'outlook.live.com', storedConsent = null, bodyInitiallyAvailable = true } = {}) {
  const values = { trackingThreatsEmailConsent: storedConsent, trackingThreatsEmailBatchSize: 10 }
  const listeners = { document: {}, window: {}, runtime: null }
  const visibleUi = new Set()
  const stats = { prompts: 0, starts: 0, writes: 0 }
  const mutationObservers = []
  const timers = new Map()
  let nextTimerId = 0
  const sandbox = {
    chrome: {
      storage: { local: {
        get: async (key) => ({ [key]: values[key] }),
        set: async (update) => { Object.assign(values, update); stats.writes += 1 },
      } },
      runtime: { onMessage: { addListener: (listener) => { listeners.runtime = listener } } },
    },
    document: {
      body: bodyInitiallyAvailable ? {} : null,
      documentElement: {},
      addEventListener: (name, callback) => { listeners.document[name] = callback },
      getElementById: (id) => visibleUi.has(id) ? { remove: () => visibleUi.delete(id) } : null,
      querySelectorAll: () => [],
    },
    window: {
      location: { hostname },
      addEventListener: (name, callback) => { listeners.window[name] = callback },
      removeEventListener: () => {},
      clearTimeout: (id) => timers.delete(id),
      setTimeout: (callback, delay) => {
        const id = ++nextTimerId
        timers.set(id, { callback, delay })
        return id
      },
    },
    MutationObserver: class {
      constructor(callback) { this.callback = callback; this.disconnected = false; mutationObservers.push(this) }
      observe() {}
      disconnect() { this.disconnected = true }
    },
    URL,
    values,
    stats,
    visibleUi,
    listeners,
    mutationObservers,
    timers,
    setConsentTestBody: () => { sandbox.document.body = {} },
  }
  vm.runInNewContext(`${configSource}\n${source}
    showEmailConsentDialog = () => {
      if (!document.body || visibleUi.has('threattrack-email-consent')) return
      visibleUi.add('threattrack-email-consent')
      stats.prompts += 1
    }
    showEmailScanningDisabled = () => visibleUi.add('threattrack-email-consent-disabled')
    startEmailMonitoring = () => {
      if (emailConsentGranted) return
      stopConsentRecoveryObserver()
      emailConsentGranted = true
      stats.starts += 1
    }
    globalThis.consentHarness = {
      ready: () => handleEmailConsentPageReady(),
      values,
      stats,
      visibleUi,
      listeners,
      granted: () => emailConsentGranted,
      saveConsent: saveEmailConsent,
      removeDialog: () => visibleUi.delete('threattrack-email-consent'),
      renderBody: () => setConsentTestBody(),
      triggerMutation: () => mutationObservers.filter((observer) => !observer.disconnected).forEach((observer) => observer.callback([])),
      flushTimers: () => {
        const pending = Array.from(timers.values())
        timers.clear()
        pending.forEach(({ callback }) => callback())
      },
      activeConsentObservers: () => mutationObservers.filter((observer) => !observer.disconnected).length,
    }
  `, sandbox, { filename: fileURLToPath(new URL('./email-monitor.js', import.meta.url)) })
  return sandbox.consentHarness
}

const fixtureElement = (textContent, { attributes = {}, links = [], descendants = {} } = {}) => ({
  textContent,
  href: attributes.href,
  descendants,
  getAttribute: (name) => attributes[name] ?? null,
  getBoundingClientRect: () => ({ width: 120, height: 24 }),
  querySelectorAll: (selector) => selector === 'a[href]' ? links : descendants[selector] ?? [],
})

const openedMessage = (prefix = 'Important account notice') => {
  const visibleLink = fixtureElement('Review', {
    attributes: { href: 'https://accounts.example.test/verify?source=mail' },
  })
  return {
    sender: fixtureElement('Security Team <security@example.test>', { attributes: { email: 'security@example.test' } }),
    subject: fixtureElement(`${prefix}: action requested`),
    body: fixtureElement('Please review this account notice and verify your details using the secure link provided in this message.', {
      links: [visibleLink],
    }),
  }
}

const providerFixtures = [
  {
    name: 'Gmail', hostname: 'mail.google.com', selectors: ['.gD[email]', 'h2.hP', '.a3s.aiL'],
    map: (message) => ({ '.gD[email]': [message.sender], 'h2.hP': [message.subject], '.a3s.aiL': [message.body] }),
  },
  {
    name: 'Outlook', hostname: 'outlook.live.com', selectors: [
      '[data-testid="message-header"] [title*="@"]', '[role="heading"][aria-level="1"]', '[aria-label="Message body"]',
    ],
    map: (message) => ({
      '[data-testid="message-header"] [title*="@"]': [fixtureElement('security@example.test')],
      '[role="heading"][aria-level="1"]': [message.subject],
      '[aria-label="Message body"]': [message.body],
    }),
  },
  {
    name: 'Outlook Cloud', hostname: 'outlook.cloud.microsoft', selectors: [
      '[aria-label="Reading Pane"]', '[aria-label="Email message"]', '[aria-label^="From" i]',
      '[role="heading"]', '[aria-label="Message body"]',
    ],
    expectedSender: 'Campus Ministry',
    expectedSubject: 'NOVENA AND FEAST OF OUR LADY OF THE MIRACULOUS MEDAL (Cir.#06, S. 26-27)',
    map: (message) => {
      const sender = fixtureElement('Campus Ministry', { attributes: { 'aria-label': 'From: Campus Ministry' } })
      const subject = fixtureElement('NOVENA AND FEAST OF OUR LADY OF THE MIRACULOUS MEDAL (Cir.#06, S. 26-27)')
      const body = fixtureElement('Please review this account notice and verify your details using the secure link provided in this message.', {
        links: message.body.querySelectorAll('a[href]'),
      })
      const emailMessage = fixtureElement('Campus Ministry To: signed-in-user@example.test 10:30 AM', {
        descendants: {
          '[aria-label^="From" i]': [sender],
          '[role="heading"]': [subject],
          '[aria-label="Message body"]': [body],
        },
      })
      const readingPane = fixtureElement('Opened email details', {
        descendants: { '[aria-label="Email message"]': [emailMessage] },
      })
      return {
        '[aria-label="Reading Pane"]': [readingPane],
        // These page-level values must not override the selected message values.
        '[aria-label^="From" i]': [fixtureElement('Signed-in account')],
        '[role="heading"]': [fixtureElement('Inbox preview subject')],
        '[aria-label="Message body"]': [fixtureElement('Unrelated preview text')],
      }
    },
  },
  {
    name: 'Yahoo Mail', hostname: 'mail.yahoo.com', selectors: [
      '[data-test-id="message-view-from"]', '[data-test-id="message-view-subject"]', '[data-test-id="message-view-body"]',
    ],
    map: (message) => ({
      '[data-test-id="message-view-from"]': [message.sender],
      '[data-test-id="message-view-subject"]': [message.subject],
      '[data-test-id="message-view-body"]': [message.body],
    }),
  },
  {
    name: 'Proton Mail', hostname: 'mail.proton.me', selectors: [
      '[data-testid*="sender"]', '[data-testid*="subject"]', '[data-testid*="message-content"]',
    ],
    map: (message) => ({
      '[data-testid*="sender"]': [message.sender],
      '[data-testid*="subject"]': [message.subject],
      '[data-testid*="message-content"]': [message.body],
    }),
  },
  {
    name: 'iCloud Mail', hostname: 'www.icloud.com', selectors: [
      '[aria-label*="From"]', '[aria-label*="Subject"]', '[aria-label="Message body"]',
    ],
    map: (message) => ({
      '[aria-label*="From"]': [message.sender],
      '[aria-label*="Subject"]': [message.subject],
      '[aria-label="Message body"]': [message.body],
    }),
  },
  {
    name: 'Zoho Mail generic adapter', hostname: 'mail.zoho.com', selectors: [
      '[data-testid*="sender"]', '[data-testid*="subject"]', '[data-testid*="message-body"]',
    ],
    map: (message) => ({
      '[data-testid*="sender"]': [message.sender],
      '[data-testid*="subject"]': [message.subject],
      '[data-testid*="message-body"]': [message.body],
    }),
  },
]

const rows = (start, count) => Array.from({ length: count }, (_, offset) => ({
  id: `thread-${start + offset}`,
  dataset: {},
  email: {
    sender: `sender${start + offset}@example.com`,
    subject: `Message ${start + offset}`,
    body: 'Private preview text that must not enter the review list',
  },
}))

function settleCallbacks(callbacks) {
  while (callbacks.length) callbacks.shift()({ ok: true, scan: { status: 'Safe', score: 100 } })
}

test('Gmail inbox pauses after 50 attempts and requires a choice for the next 50', () => {
  const { monitor, callbacks } = createMonitor()
  monitor.setBatchSize(50)
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

test('failed scans remain retryable and continuing waits for new messages in the selected view', () => {
  const { monitor, callbacks } = createMonitor()
  monitor.setBatchSize(50)
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

test('Gmail waits for newly rendered rows and scans only to the selected batch limit', () => {
  const { monitor, callbacks } = createMonitor()
  monitor.setBatchSize(50)
  monitor.setRows(rows(0, 45))
  monitor.scan()
  for (let index = 0; index < 45; index += 1) {
    callbacks.shift()({ ok: true, scan: { status: 'Safe', score: 100 } })
  }
  assert.equal(monitor.state().attempts, 45)
  assert.equal(monitor.state().paused, false)
  assert.equal(monitor.state().waiting, true)
  assert.equal(monitor.state().reviewPrompts, 0)

  monitor.setRows(rows(0, 60))
  monitor.scan()
  for (let index = 0; index < 5; index += 1) {
    callbacks.shift()({ ok: true, scan: { status: 'Safe', score: 100 } })
  }
  assert.equal(monitor.state().attempts, 50)
  assert.equal(monitor.state().paused, true)
  assert.equal(callbacks.length, 0)
})

test('Gmail respects selectable batch sizes from 10 through 50', () => {
  for (const size of [10, 20, 30, 40, 50]) {
    const { monitor, callbacks } = createMonitor()
    monitor.setBatchSize(size)
    monitor.setRows(rows(0, 60))
    monitor.scan()

    for (let index = 0; index < size; index += 1) {
      callbacks.shift()({ ok: true, scan: { status: 'Safe', score: 100 } })
    }

    assert.equal(monitor.state().batchSize, size)
    assert.equal(monitor.state().attempts, size)
    assert.equal(monitor.state().paused, true)
    assert.equal(callbacks.length, 0)
  }
})

test('Gmail folder changes discard prior batch results and scan only the newly selected view', () => {
  const { monitor, callbacks, messages } = createMonitor()
  monitor.setRows(rows(0, 4))
  monitor.scan()
  settleCallbacks(callbacks)
  assert.equal(monitor.state().results.length, 4)

  monitor.setHash('#sent')
  monitor.setRows(rows(100, 3))
  monitor.scan()
  assert.equal(monitor.state().viewId, 'sent')
  assert.equal(monitor.state().results.length, 0)
  monitor.scan()
  assert.equal(messages.length, 7)
  assert.ok(messages.slice(4).every(({ email }) => email.sender.includes('sender10')))
})

test('Gmail renders the batch-size selector before consent, in the monitor, and beside review actions', () => {
  const consentSource = source.slice(
    source.indexOf('function showEmailConsentDialog('),
    source.indexOf('function cleanText('),
  )
  const statusSource = source.slice(
    source.indexOf('function showInboxStatus('),
    source.indexOf('function continueInboxBatch('),
  )
  const reviewSource = source.slice(
    source.indexOf('function showInboxReview('),
    source.indexOf('function getOutlookEmail('),
  )

  assert.match(source, /const INBOX_BATCH_SIZES = \[10, 20, 30, 40, 50\]/)
  assert.match(consentSource, /batchText\.textContent = 'Emails to scan per batch'/)
  assert.match(consentSource, /createInboxBatchSizeSelect\(\)/)
  assert.match(statusSource, /batchLabel\.textContent = inboxPaused \? 'Next batch size' : 'Batch size'/)
  assert.match(statusSource, /banner\.append\(header, body, counts, totals, batchControls\)/)
  assert.match(reviewSource, /actions\.append\(batchSelect, next\)/)
  assert.match(source, /showInboxStatus\(\)[\s\S]*?startOutlookCloudRouteMonitor\(\)[\s\S]*?scheduleEmailChecks\(\)/)
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

test('safe email labels distinguish complete scans from limited checks', () => {
  const { monitor } = createMonitor()
  const complete = { status: 'complete', checkedProviders: 1, totalProviders: 1, linksChecked: 0, totalLinks: 0 }
  const limited = { status: 'local-only', checkedProviders: 0, totalProviders: 0 }

  assert.equal(monitor.getStatusLabel('Safe', complete), 'No warning found')
  assert.equal(monitor.getScanLevel({ status: 'Safe', coverage: complete }), 'safe')
  assert.equal(monitor.getStatusLabel('Safe', limited), 'No warning found - limited check')
  assert.equal(monitor.getScanLevel({ status: 'Safe', coverage: limited }), 'incomplete')
})

test('opened email warning offers expandable scan details and keeps its History link', () => {
  const disclosureSource = source.slice(
    source.indexOf('function appendScanDetailsDisclosure('),
    source.indexOf('const MIN_EMAIL_TEXT_LENGTH'),
  )
  const warningSource = source.slice(
    source.indexOf('function showEmailWarning('),
    source.indexOf('function showInboxRiskWarning('),
  )

  assert.match(disclosureSource, /document\.createElement\('details'\)/)
  assert.match(disclosureSource, /document\.createElement\('summary'\)/)
  assert.match(disclosureSource, /summary\.textContent = 'View more details'/)
  assert.match(warningSource, /appendScanDetailsDisclosure\(banner, scan\)/)
  assert.match(warningSource, /details\.textContent = 'Open scan details'/)
})

test('provider adapters return only normalized opened-message data and preserve visible links', () => {
  for (const provider of providerFixtures) {
    const message = openedMessage(provider.name)
    const { monitor } = createMonitor({ hostname: provider.hostname, selectorMap: provider.map(message) })
    const email = monitor.getOpenedEmail()

    assert.ok(email, `${provider.name} should identify the fixture message`)
    assert.deepEqual(Object.keys(email).sort(), ['body', 'links', 'sender', 'subject'])
    if (provider.expectedSender) assert.equal(email.sender, provider.expectedSender)
    else assert.match(email.sender, /security@example\.test/)
    assert.equal(email.subject, provider.expectedSubject ?? `${provider.name}: action requested`)
    assert.match(email.body, /Please review this account notice/)
    assert.match(email.body, /Visible links:/)
    assert.deepEqual(Array.from(email.links), ['https://accounts.example.test/verify?source=mail'])
    assert.equal('recipient' in email, false)
  }
})

test('Outlook Cloud opened-message data is submitted through the existing email scan route', () => {
  const provider = providerFixtures.find(({ hostname }) => hostname === 'outlook.cloud.microsoft')
  const message = openedMessage('Outlook Cloud')
  const { monitor, messages } = createMonitor({ hostname: provider.hostname, selectorMap: provider.map(message) })
  const extracted = monitor.getOpenedEmail()
  monitor.scanOpened()

  assert.equal(extracted.sender, 'Campus Ministry')
  assert.equal(extracted.subject, provider.expectedSubject)
  assert.equal(messages.length, 1)
  assert.equal(messages[0].type, 'scan-email-content')
  assert.equal(messages[0].email.sender, 'Campus Ministry')
  assert.equal(messages[0].email.subject, provider.expectedSubject)
  assert.match(backgroundSource, /const EMAIL_API_URL = `\$\{API_BASE_URL\}\/api\/scan\/email`/)
  assert.match(backgroundSource, /await scanFetch\(EMAIL_API_URL,\s*\{[\s\S]*?body: JSON\.stringify\(/)
})

test('individual email results retain backend classification fields for the existing warning details', () => {
  const provider = providerFixtures.find(({ hostname }) => hostname === 'outlook.cloud.microsoft')
  const { monitor, callbacks, warningScans } = createMonitor({
    hostname: provider.hostname,
    selectorMap: provider.map(openedMessage('Outlook Cloud')),
  })
  const scan = {
    status: 'Dangerous',
    score: 24,
    threatName: 'Suspected phishing email',
    threatType: 'Phishing / credential theft',
    whyDetected: ['The message requests credentials through an unfamiliar link.'],
    evidenceSources: ['Email content rules'],
  }

  monitor.scanOpened()
  callbacks[0]({ ok: true, scan })
  assert.equal(warningScans[0].threatName, scan.threatName)
  assert.equal(warningScans[0].threatType, scan.threatType)
  assert.deepEqual(Array.from(warningScans[0].whyDetected), scan.whyDetected)
  assert.deepEqual(Array.from(warningScans[0].evidenceSources), scan.evidenceSources)
})

test('shared email scan details render threat reasons, evidence, status, and limitations', () => {
  const { monitor } = createMonitor({ hostname: 'outlook.cloud.microsoft' })
  const parent = { children: [], appendChild(child) { this.children.push(child) } }
  monitor.renderScanContext(parent, {
    status: 'Dangerous',
    score: 18,
    coverage: {
      status: 'partial',
      checkedProviders: 1,
      totalProviders: 2,
      limitations: ['One reputation provider was unavailable.'],
    },
    categories: ['phishing-indicators'],
    threatName: 'Suspected phishing email',
    threatType: 'Phishing / credential theft',
    confidence: 'Medium',
    whyDetected: ['The message requests account credentials through an unfamiliar link.'],
    evidenceSources: ['Email content rules', 'PhishTank'],
  })
  const text = monitor.renderedTexts().join('\n')
  assert.match(text, /Threat name: Suspected phishing email/)
  assert.match(text, /Threat type: Phishing \/ credential theft/)
  assert.match(text, /Why detected:/)
  assert.match(text, /The message requests account credentials/)
  assert.match(text, /Evidence sources: Email content rules, PhishTank/)
  assert.match(text, /Risk detected \(18\/100\)/)
  assert.match(text, /unavailable or skipped/i)
  assert.match(text, /One reputation provider was unavailable/)
  assert.match(text, /Scan finished/)
})

test('safe email details explain a neutral result and label reputation providers as checked sources', () => {
  const { monitor } = createMonitor()
  const parent = { children: [], appendChild(child) { this.children.push(child) } }
  monitor.renderScanContext(parent, {
    status: 'Safe',
    score: 100,
    coverage: { status: 'complete', checkedProviders: 2, totalProviders: 2, limitations: [] },
    categories: [],
    threatName: 'No threat identified',
    threatType: 'None detected',
    confidence: 'No threat detected',
    whyDetected: ['No strong threat indicators were found in the checks that ran.'],
    evidenceSources: ['PhishTank', 'Google Safe Browsing'],
  })
  const text = monitor.renderedTexts().join('\n')
  assert.match(text, /Threat name: No threat identified/)
  assert.match(text, /Result explanation:/)
  assert.match(text, /Sources checked: PhishTank, Google Safe Browsing/)
  assert.doesNotMatch(text, /Why detected:/)
  assert.doesNotMatch(text, /Suspected phishing|verified phishing/i)
})

test('email scan details handle missing optional fields without inventing threat evidence', () => {
  const { monitor } = createMonitor()
  const parent = { children: [], appendChild(child) { this.children.push(child) } }
  monitor.renderScanContext(parent, {
    status: 'Safe',
    score: 100,
    coverage: { status: 'local-only', checkedProviders: 0, totalProviders: 0, limitations: ['Reputation providers were not checked.'] },
    categories: [],
  })
  const text = monitor.renderedTexts().join('\n')
  assert.match(text, /No specific threat indicators were returned by the available checks/)
  assert.match(text, /No warning found - limited check/)
  assert.match(text, /Reputation providers were not checked/)
  assert.doesNotMatch(text, /Threat name:|Threat type:|Evidence sources:|Sources checked:/)
})

test('Outlook Cloud scans a sufficiently long opened body when sender and subject are unavailable', () => {
  const provider = providerFixtures.find(({ hostname }) => hostname === 'outlook.cloud.microsoft')
  const selectorMap = provider.map(openedMessage('Outlook Cloud'))
  const readingPane = selectorMap['[aria-label="Reading Pane"]'][0]
  const emailMessage = readingPane.querySelectorAll('[aria-label="Email message"]')[0]
  delete emailMessage.descendants['[aria-label^="From" i]']
  delete emailMessage.descendants['[role="heading"]']

  const { monitor, messages } = createMonitor({ hostname: provider.hostname, selectorMap })
  const extracted = monitor.getOpenedEmail()
  assert.equal(extracted.sender, '')
  assert.equal(extracted.subject, '')
  monitor.scanOpened()
  assert.equal(messages.length, 1)
  assert.ok(messages[0].email.body.length >= 40)
})

test('Outlook Cloud batch extraction requires an individual email element with sender, subject, and body', () => {
  const body = fixtureElement('This is the complete visible email body and contains enough text to scan safely.', {
    links: [fixtureElement('Review', { attributes: { href: 'https://example.test/account' } })],
  })
  const openedMessageElement = fixtureElement('Individual message content', {
    descendants: {
      '[aria-label^="From" i]': [fixtureElement('Sender <sender@example.test>')],
      '[aria-label^="Subject" i]': [fixtureElement('A specific email subject')],
      '[data-test-id="mailMessageBodyContainer"]': [body],
    },
  })
  const { monitor } = createMonitor({ hostname: 'outlook.cloud.microsoft' })
  assert.equal(monitor.outlookFolderId(), 'inbox')
  const extracted = monitor.extractOutlookBatchMessage(openedMessageElement)
  assert.equal(extracted.sender, 'Sender <sender@example.test>')
  assert.equal(extracted.subject, 'A specific email subject')
  assert.match(extracted.body, /complete visible email body/)
  assert.deepEqual(Array.from(extracted.links), ['https://example.test/account'])
  assert.equal(monitor.extractOutlookBatchMessage(null), null)
})

test('Outlook Cloud folder detection accepts explicit routes and a single selected folder on /mail/', () => {
  const { monitor } = createMonitor({ hostname: 'outlook.cloud.microsoft', pathname: '/mail/' })
  monitor.setMessageLists([outlookMessageList('Message list No conversations selected')])
  monitor.setTreeItems([outlookTreeItem('inbox')])
  assert.equal(monitor.outlookFolderId(), 'inbox')
  assert.equal(monitor.outlookAvailability().enabled, true)

  monitor.setTreeItems([outlookTreeItem(' Sent Items ', true, 'Sent Items - 38 items')])
  assert.equal(monitor.outlookFolderId(), 'sentitems')
  assert.equal(monitor.outlookAvailability().enabled, true)

  monitor.setTreeItems([outlookTreeItem('Archive')])
  assert.equal(monitor.outlookFolderId(), null)
  assert.equal(monitor.outlookAvailability().enabled, false)
  assert.match(monitor.outlookAvailability().message, /Inbox and Sent Items folders/)

  monitor.setTreeItems([outlookTreeItem('Inbox')])
  monitor.setMessageLists([])
  assert.equal(monitor.outlookFolderId(), null)

  monitor.setPathname('/mail/inbox/id/account')
  assert.equal(monitor.outlookFolderId(), 'inbox')
  monitor.setPathname('/mail/sentitems/id/account')
  assert.equal(monitor.outlookFolderId(), 'sentitems')
})

test('Outlook Cloud fallback rejects ambiguous selections and ignores unselected Favorites shortcuts', () => {
  const { monitor } = createMonitor({ hostname: 'outlook.cloud.microsoft', pathname: '/mail/' })
  monitor.setMessageLists([outlookMessageList('Message list No conversations selected')])
  monitor.setTreeItems([
    outlookTreeItem('inbox', false, 'Favorites Inbox'),
    outlookTreeItem('inbox', true, 'Inbox - 1,344 items (1,281 unread)'),
  ])
  assert.equal(monitor.outlookFolderId(), 'inbox')

  monitor.setTreeItems([outlookTreeItem('Inbox'), outlookTreeItem('Sent Items')])
  assert.equal(monitor.outlookFolderId(), null)
  monitor.setTreeItems([outlookTreeItem('Junk Email')])
  assert.equal(monitor.outlookFolderId(), null)
})

test('Outlook Cloud monitoring refreshes on pathname or selected-folder changes only', () => {
  const { monitor, intervalCount, tickRouteMonitor } = createMonitor({ hostname: 'outlook.cloud.microsoft', pathname: '/mail/' })
  monitor.setMessageLists([outlookMessageList('Message list No conversations selected')])
  monitor.setTreeItems([outlookTreeItem('Archive')])
  monitor.start()
  assert.equal(intervalCount(), 1)
  assert.equal(monitor.outlookAvailability().enabled, false)

  const initialRefreshes = monitor.state().inboxStatusRefreshes
  monitor.setTreeItems([outlookTreeItem('Inbox')])
  tickRouteMonitor()
  assert.equal(monitor.outlookFolderId(), 'inbox')
  assert.equal(monitor.outlookAvailability().enabled, true)
  assert.equal(monitor.outlookAvailability().message, '')
  assert.equal(monitor.state().inboxStatusRefreshes, initialRefreshes + 1)

  monitor.setTreeItems([outlookTreeItem('Sent Items')])
  tickRouteMonitor()
  assert.equal(monitor.outlookFolderId(), 'sentitems')
  assert.equal(monitor.outlookAvailability().enabled, true)
  assert.equal(monitor.state().inboxStatusRefreshes, initialRefreshes + 2)

  monitor.setTreeItems([outlookTreeItem('Archive')])
  tickRouteMonitor()
  assert.equal(monitor.outlookFolderId(), null)
  assert.equal(monitor.outlookAvailability().enabled, false)
  assert.equal(monitor.state().inboxStatusRefreshes, initialRefreshes + 3)

  tickRouteMonitor()
  monitor.refreshOutlookRoute()
  assert.equal(monitor.state().inboxStatusRefreshes, initialRefreshes + 3)

  monitor.setPathname('/mail/sentitems/id/account')
  tickRouteMonitor()
  assert.equal(monitor.outlookFolderId(), 'sentitems')
  assert.equal(monitor.state().inboxStatusRefreshes, initialRefreshes + 4)

  monitor.stop()
  assert.equal(intervalCount(), 0)
})

test('Outlook Cloud route monitoring is not started on Gmail and the panel remains consent-gated', () => {
  const gmail = createMonitor()
  gmail.monitor.start()
  assert.equal(gmail.intervalCount(), 0)
  gmail.monitor.stop()

  const routeMonitorSource = source.slice(source.indexOf('function startOutlookCloudRouteMonitor'), source.indexOf('function extractOutlookCloudBatchMessage'))
  assert.match(routeMonitorSource, /hostname !== 'outlook\.cloud\.microsoft'/)
  const statusSource = source.slice(source.indexOf('function showInboxStatus'), source.indexOf('function getOutlookEmail'))
  assert.match(statusSource, /if \(!emailConsentGranted[\s\S]*?return/)
  assert.match(source.slice(source.indexOf('function startEmailMonitoring'), source.indexOf('async function refreshEmailConsentUi')), /showInboxStatus\(\)[\s\S]*?startOutlookCloudRouteMonitor\(\)/)
})

test('inbox-only and uncertain provider views are not submitted', () => {
  const inboxView = createMonitor({
    hostname: 'mail.zoho.com',
    selectorMap: {
      main: [fixtureElement('Inbox navigation and unrelated message previews')],
      article: [fixtureElement('A long preview from an unrelated inbox row that must not be scanned.')],
      '[role="document"]': [fixtureElement('Page level content that is not a selected message.')],
      h1: [fixtureElement('Inbox')],
    },
  })
  assert.equal(inboxView.monitor.getOpenedEmail(), null)
  inboxView.monitor.scanOpened()
  assert.equal(inboxView.callbacks.length, 0)

  const uncertain = createMonitor({
    hostname: 'outlook.office.com',
    selectorMap: {
      '[data-testid="message-header"] [title*="@"]': [fixtureElement('security@example.test')],
      '[role="heading"][aria-level="1"]': [fixtureElement('Subject shown in a list')],
      main: [fixtureElement('Broad page text without a recognized message-body marker.')],
    },
  })
  assert.equal(uncertain.monitor.getOpenedEmail(), null)
  uncertain.monitor.scanOpened()
  assert.equal(uncertain.callbacks.length, 0)

  const unsupported = createMonitor({
    hostname: 'mail.google.com.attacker.test',
    selectorMap: providerFixtures[0].map(openedMessage()),
  })
  assert.equal(unsupported.monitor.getOpenedEmail(), null)
  unsupported.monitor.scanOpened()
  assert.equal(unsupported.callbacks.length, 0)
})

test('MutationObserver duplicate events deduplicate scans and message switching scans new content', () => {
  const selectorMap = providerFixtures[0].map(openedMessage('First Gmail message'))
  const { monitor, callbacks, observerCallbacks, warningScans, flushTimers } = createMonitor({ selectorMap })
  monitor.start()
  assert.equal(observerCallbacks.length, 1)

  observerCallbacks[0]()
  observerCallbacks[0]()
  flushTimers(1400)
  assert.equal(callbacks.length, 1)

  observerCallbacks[0]()
  observerCallbacks[0]()
  flushTimers(1400)
  assert.equal(callbacks.length, 1)

  const nextMessage = openedMessage('Second Gmail message')
  selectorMap['.gD[email]'] = [nextMessage.sender]
  selectorMap['h2.hP'] = [nextMessage.subject]
  selectorMap['.a3s.aiL'] = [nextMessage.body]
  observerCallbacks[0]()
  flushTimers(1400)
  assert.equal(callbacks.length, 2)

  callbacks[0]({ ok: true, scan: { status: 'Dangerous' } })
  assert.equal(warningScans.length, 0)
  callbacks[1]({ ok: true, scan: { status: 'Suspicious' } })
  assert.equal(warningScans.length, 1)
  monitor.stop()
})

test('opened-message scans ignore in-flight results after consent withdrawal', () => {
  const message = openedMessage('Outlook message')
  const { monitor, callbacks, warningScans } = createMonitor({
    hostname: 'outlook.live.com',
    selectorMap: providerFixtures[1].map(message),
  })
  monitor.scanOpened()
  assert.equal(callbacks.length, 1)
  monitor.stop()
  callbacks[0]({ ok: true, scan: { status: 'Dangerous' } })
  assert.equal(warningScans.length, 0)
})

test('opened-email API failures are shown and can be retried independently of Gmail batches', () => {
  const message = openedMessage('Outlook message')
  const { monitor, callbacks, warningScans, messages } = createMonitor({
    hostname: 'outlook.live.com',
    selectorMap: providerFixtures[1].map(message),
  })
  monitor.scanOpened()
  callbacks.shift()({ ok: false, error: 'Temporary API failure' })
  assert.equal(monitor.state().failurePrompts, 1)
  assert.equal(warningScans.length, 0)

  monitor.scanOpened()
  assert.equal(messages.length, 2)
  callbacks.shift()({ ok: true, scan: { status: 'Safe' } })
  assert.equal(warningScans.length, 1)
})

test('consent decline and withdrawal stop monitoring before persisting the decision', () => {
  const disableSource = source.slice(
    source.indexOf('async function disableEmailMonitoring('),
    source.indexOf('function createTurnOffButton('),
  )
  const consentSource = source.slice(
    source.indexOf('function showEmailConsentDialog('),
    source.indexOf('function cleanText('),
  )
  assert.match(disableSource, /stopEmailMonitoring\(\)\s+await saveEmailConsent\(false\)/)
  assert.match(consentSource, /decline\.addEventListener\('click',[\s\S]*?stopEmailMonitoring\(\)[\s\S]*?saveEmailConsent\(false\)/)
  assert.match(source, /const EMAIL_CONSENT_VERSION = '2026\.12'/)
  assert.match(backgroundSource, /const EMAIL_CONSENT_VERSION = '2026\.12'/)
})

test('Outlook consent returns after login reload and remains unaccepted until explicit acceptance', async () => {
  const beforeLogin = createConsentLifecycle({ hostname: 'outlook.live.com' })
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(beforeLogin.stats.prompts, 1)
  assert.equal(beforeLogin.stats.writes, 0)
  assert.equal(beforeLogin.granted(), false)

  // A document reload creates a new content-script instance with the same extension storage.
  const afterLogin = createConsentLifecycle({ hostname: 'outlook.live.com', storedConsent: beforeLogin.values.trackingThreatsEmailConsent })
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(afterLogin.stats.prompts, 1)
  assert.equal(afterLogin.stats.starts, 0)
  assert.equal(afterLogin.granted(), false)
  assert.equal(afterLogin.stats.writes, 0)

  await afterLogin.saveConsent(true)
  afterLogin.ready()
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(afterLogin.granted(), true)
  assert.equal(afterLogin.stats.starts, 1)
  assert.equal(afterLogin.values.trackingThreatsEmailConsent.noticeVersion, '2026.12')
})

test('valid consent does not prompt again and SPA lifecycle events do not duplicate the dialog', async () => {
  const accepted = createConsentLifecycle({
    hostname: 'outlook.office.com',
    storedConsent: { accepted: true, noticeVersion: '2026.12' },
  })
  await new Promise((resolve) => setImmediate(resolve))
  accepted.ready()
  accepted.listeners.window.pageshow()
  accepted.listeners.window.popstate()
  accepted.listeners.window.hashchange()
  accepted.listeners.document.DOMContentLoaded()
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(accepted.stats.prompts, 0)
  assert.equal(accepted.stats.starts, 1)
  assert.equal(accepted.granted(), true)
  assert.equal(accepted.activeConsentObservers(), 0)
  accepted.triggerMutation()
  assert.equal(accepted.stats.prompts, 0)

  const pending = createConsentLifecycle({ hostname: 'outlook.live.com' })
  await new Promise((resolve) => setImmediate(resolve))
  pending.listeners.window.popstate()
  pending.listeners.window.hashchange()
  pending.listeners.window.pageshow()
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(pending.stats.prompts, 1)
  assert.equal(pending.granted(), false)
})

test('Outlook consent appears after inbox rendering and is restored if Outlook removes it', async () => {
  const delayedInbox = createConsentLifecycle({ hostname: 'outlook.live.com', bodyInitiallyAvailable: false })
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(delayedInbox.stats.prompts, 0)
  delayedInbox.renderBody()
  delayedInbox.triggerMutation()
  delayedInbox.flushTimers()
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(delayedInbox.stats.prompts, 1)

  const rerenderedInbox = createConsentLifecycle({ hostname: 'outlook.office.com' })
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(rerenderedInbox.stats.prompts, 1)
  rerenderedInbox.removeDialog()
  rerenderedInbox.triggerMutation()
  rerenderedInbox.triggerMutation()
  rerenderedInbox.triggerMutation()
  rerenderedInbox.flushTimers()
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(rerenderedInbox.stats.prompts, 2)
  assert.equal(rerenderedInbox.activeConsentObservers(), 1)

  rerenderedInbox.triggerMutation()
  rerenderedInbox.triggerMutation()
  rerenderedInbox.flushTimers()
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(rerenderedInbox.stats.prompts, 2)
})

test('Gmail still prompts for current consent and popup can reopen consent on supported webmail', async () => {
  const gmail = createConsentLifecycle({ hostname: 'mail.google.com' })
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(gmail.stats.prompts, 1)
  assert.equal(gmail.granted(), false)

  const reopen = createConsentLifecycle({ hostname: 'outlook.cloud.microsoft' })
  await new Promise((resolve) => setImmediate(resolve))
  reopen.removeDialog()
  let reply
  reopen.listeners.runtime({ type: 'review-email-consent' }, {}, (value) => { reply = value })
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(reply.ok, true)
  assert.equal(reopen.stats.prompts, 2)
  assert.match(popupSource, /tabs\.query\(\{ active: true, currentWindow: true \}/)
  assert.match(popupSource, /activeUrl\.protocol === 'https:' && isSupportedEmailHost\(activeUrl\.hostname\)/)
  assert.match(popupSource, /tabs\.sendMessage\(tab\.id, \{ type: 'review-email-consent' \}/)
})

test('supported sender validation rejects unsupported sites, frames, schemes, and mismatched tabs', () => {
  const security = { URL }
  vm.runInNewContext(`${configSource}\nglobalThis.emailSecurity = { isSupportedEmailHost, isSupportedEmailSender }`, security, {
    filename: fileURLToPath(new URL('./config.js', import.meta.url)),
  })
  const { isSupportedEmailHost, isSupportedEmailSender } = security.emailSecurity
  for (const hostname of [
    'mail.google.com', 'outlook.cloud.microsoft', 'outlook.live.com', 'outlook.office.com', 'outlook.office365.com',
    'mail.yahoo.com', 'mail.proton.me', 'app.proton.me', 'www.icloud.com', 'mail.zoho.com',
    'mail.aol.com', 'mail.com', 'accounts.mail.com',
  ]) assert.equal(isSupportedEmailHost(hostname), true, hostname)
  for (const hostname of ['outlook.cloud.microsoft.evil.test', 'outlook.com', 'mail.evil.test']) {
    assert.equal(isSupportedEmailHost(hostname), false, hostname)
  }
  const emailMatches = manifest.content_scripts.find(({ js }) => js.includes('email-monitor.js')).matches
  for (const pattern of [
    'https://mail.google.com/*', 'https://outlook.cloud.microsoft/*', 'https://outlook.live.com/*', 'https://outlook.office.com/*',
    'https://outlook.office365.com/*', 'https://mail.yahoo.com/*', 'https://mail.proton.me/*',
    'https://app.proton.me/*', 'https://www.icloud.com/*', 'https://mail.zoho.com/*',
    'https://mail.aol.com/*', 'https://*.mail.com/*',
  ]) assert.equal(emailMatches.includes(pattern), true, pattern)

  const sender = (url, tabUrl = url, frameId = 0) => ({
    url,
    frameId,
    tab: { id: 7, url: tabUrl },
  })
  assert.equal(isSupportedEmailSender(sender('https://mail.google.com/mail/u/0/')), true)
  assert.equal(isSupportedEmailSender(sender('https://outlook.cloud.microsoft/mail/')), true)
  assert.equal(isSupportedEmailSender(sender('https://outlook.cloud.microsoft/mail/', 'https://outlook.office.com/mail/')), false)
  assert.equal(isSupportedEmailSender(sender('https://mail.yahoo.com/', 'https://mail.yahoo.com/')), true)
  assert.equal(isSupportedEmailSender(sender('https://mail.google.com/', 'https://evil.test/')), false)
  assert.equal(isSupportedEmailSender(sender('http://mail.google.com/')), false)
  assert.equal(isSupportedEmailSender(sender('https://mail.google.com/extension-frame', undefined, 4)), false)
  assert.equal(isSupportedEmailSender({ url: 'https://mail.google.com/', frameId: 0 }), false)

  const handler = backgroundSource.slice(
    backgroundSource.indexOf("if (message?.type === 'scan-email-content')"),
    backgroundSource.indexOf("if (message?.type === 'unblock-site')"),
  )
  assert.match(handler, /if \(!isSupportedEmailSender\(sender\)\)[\s\S]*?return false[\s\S]*?scanEmailContent/)
})
