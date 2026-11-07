import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import test from 'node:test'

const engineSource = readFileSync(new URL('./email-batch.js', import.meta.url), 'utf8')
const adapterSource = readFileSync(new URL('./outlook-cloud-batch.js', import.meta.url), 'utf8')

function element({ attributes = {}, children = [], selectors = {}, onClick = null } = {}) {
  const listeners = new Map()
  return {
    parentElement: null,
    scrollTop: 0,
    clientHeight: 600,
    scrollHeight: 1200,
    getAttribute: (name) => attributes[name] ?? null,
    querySelectorAll: (selector) => selectors[selector] ?? children.filter((child) => child.matches?.(selector)),
    querySelector: (selector) => {
      const found = selectors[selector]
      return Array.isArray(found) ? found[0] ?? null : found ?? children.filter((child) => child.matches?.(selector))[0] ?? null
    },
    matches: (selector) => selector === `[role="option"][data-convid]` && attributes.role === 'option' && Boolean(attributes['data-convid']),
    addEventListener: (name, callback) => listeners.set(name, callback),
    removeEventListener: (name) => listeners.delete(name),
    dispatch: (name) => listeners.get(name)?.(),
    click: () => onClick?.(),
  }
}

function createHarness({ folder = '/mail/inbox/id/account', enabled = true, conversations = [], canScanMessage = () => true } = {}) {
  let path = folder
  let currentMessages = []
  const submissions = []
  const callbacks = []
  const rows = conversations.map(({ id, messages }) => element({
    attributes: { role: 'option', 'data-convid': id },
    onClick: () => { currentMessages = messages },
  }))
  const list = element({ attributes: { role: 'listbox', 'aria-label': 'Message list No conversations selected' } })
  list.querySelectorAll = (selector) => selector === '[role="option"][data-convid]' ? rows : []
  const pane = element()
  pane.querySelectorAll = (selector) => selector === '[aria-label="Email message"]' ? currentMessages : []
  const documentRef = {
    querySelectorAll: (selector) => selector === '[role="listbox"]' ? [list]
      : selector === '[aria-label="Reading Pane"]' ? [pane] : [],
  }
  const sandbox = {
    globalThis: {},
    document: documentRef,
    window: { setTimeout, setInterval, clearInterval },
  }
  vm.runInNewContext(`${engineSource}\n${adapterSource}`, sandbox)
  const adapter = sandbox.globalThis.createOutlookCloudBatchAdapter({
    documentRef,
    windowRef: sandbox.window,
    getFolderId: () => {
      const match = path.match(/^\/mail\/(inbox|sentitems)\/id\/[^/]+$/)
      return match?.[1] ?? null
    },
    extractMessage: (message) => message.email,
    submit: (email, callback) => { submissions.push(email.messageId); callbacks.push(callback) },
    getLevel: () => 'safe',
    isEnabled: () => enabled,
    canScanMessage,
  })
  return {
    adapter, submissions, callbacks, list,
    setFolder: (value) => { path = value },
    setEnabled: (value) => { enabled = value },
    addConversation: (id, messages) => rows.push(element({
      attributes: { role: 'option', 'data-convid': id },
      onClick: () => { currentMessages = messages },
    })),
    dispatchList: (name) => list.dispatch(name),
  }
}

async function waitUntil(predicate, timeoutMs = 2500) {
  const started = Date.now()
  while (!predicate()) {
    if (Date.now() - started > timeoutMs) throw new Error('Timed out waiting for adapter state')
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
}

function message(id, { sender = 'sender@example.test', subject = `Subject ${id}`, body = 'A complete visible message body with enough text.' } = {}) {
  const content = element({ attributes: { 'data-test-id': 'mailMessageBodyContainer' } })
  content.textContent = body
  const ancestors = Array.from({ length: 5 }, () => element())
  ancestors[4] = element({ attributes: { 'data-itempart-id': id } })
  const msg = element({
    attributes: { 'aria-label': 'Email message' },
    selectors: { '[data-test-id="mailMessageBodyContainer"], [aria-label="Message body"]': content },
  })
  msg.querySelector = (selector) => selector.includes('mailMessageBodyContainer') || selector.includes('Message body') ? content : null
  msg.parentElement = ancestors[0]
  for (let index = 0; index < ancestors.length - 1; index += 1) ancestors[index].parentElement = ancestors[index + 1]
  msg.email = { messageId: id, sender, subject, body }
  return msg
}

test('Outlook Cloud adapter recognizes only verified Inbox and Sent Items routes and conversation rows', () => {
  const harness = createHarness({ conversations: [{ id: 'conversation-1', messages: [] }] })
  assert.equal(harness.adapter.getState().viewId, 'inbox')
  assert.equal(harness.adapter.getConversationRows().length, 1)
  assert.equal(harness.adapter.getConversationId(harness.adapter.getConversationRows()[0]), 'conversation-1')
  harness.setFolder('/mail/sentitems/id/account')
  assert.equal(harness.adapter.syncFolder(), true)
  assert.equal(harness.adapter.getState().viewId, 'sentitems')
  harness.setFolder('/mail/archive/id/account')
  assert.equal(harness.adapter.syncFolder(), false)
  assert.equal(harness.adapter.getState().viewId, null)
})

test('individual message ID is read from the observed ancestor and malformed IDs are rejected', () => {
  const harness = createHarness()
  const valid = message('message-123')
  assert.equal(harness.adapter.getItempartId(valid), 'message-123')
  const invalid = message('bad\nidentifier')
  assert.equal(harness.adapter.getItempartId(invalid), '')
  assert.equal(harness.adapter.getItempartId(message('x'.repeat(257))), '')
})

test('explicit scan submits individually identified messages and labels the conversation incomplete', async () => {
  const first = message('item-1')
  const second = message('item-2')
  const harness = createHarness({ conversations: [{ id: 'conversation-a', messages: [first, second] }] })
  assert.equal(harness.adapter.start(), true)
  for (let index = 0; index < 2; index += 1) {
    await new Promise((resolve) => setTimeout(resolve, 600))
    assert.equal(harness.submissions.length, index + 1)
    harness.callbacks[index](null, { status: 'Safe', score: 100 })
  }
  await new Promise((resolve) => setTimeout(resolve, 80))
  assert.deepEqual(harness.submissions, ['item-1', 'item-2'])
  assert.equal(harness.adapter.getState().stats.checked, 2)
  assert.equal(harness.adapter.getState().adapter.conversationsIncomplete, 1)
  harness.adapter.cancel()
})

test('consent disabled prevents starting Outlook folder scanning', () => {
  const harness = createHarness()
  harness.setEnabled(false)
  assert.equal(harness.adapter.start(), false)
  assert.equal(harness.submissions.length, 0)
})

test('Outlook batches retain selectable sizes and Continue resumes the shared engine', async () => {
  for (const size of [10, 20, 30, 40, 50]) {
    const harness = createHarness()
    harness.adapter.engine.setBatchSize(size)
    assert.equal(harness.adapter.getState().batchSize, size)
  }

  const messages = Array.from({ length: 11 }, (_, index) => message(`item-${index}`))
  const harness = createHarness({ conversations: [{ id: 'thread-many', messages }] })
  harness.adapter.engine.setBatchSize(10)
  assert.equal(harness.adapter.start(), true)
  for (let index = 0; index < 10; index += 1) {
    await waitUntil(() => harness.callbacks.length > index)
    harness.callbacks[index](null, { status: 'Safe', score: 100 })
  }
  await waitUntil(() => harness.adapter.getState().paused)
  assert.equal(harness.submissions.length, 10)
  assert.equal(harness.adapter.continueBatch(), true)
  await waitUntil(() => harness.callbacks.length > 10)
  harness.callbacks[10](null, { status: 'Safe', score: 100 })
  await waitUntil(() => harness.adapter.getState().stats.checked === 11)
  assert.equal(harness.submissions.length, 11)
  harness.adapter.cancel()
})

test('virtualized list waits for manual scrolling and does not change scroll position itself', async () => {
  const first = message('item-visible-1')
  const harness = createHarness({ conversations: [{ id: 'conversation-visible-1', messages: [first] }] })
  const originalScrollTop = harness.list.scrollTop
  assert.equal(harness.adapter.start(), true)
  await waitUntil(() => harness.callbacks.length === 1)
  harness.callbacks[0](null, { status: 'Safe', score: 100 })
  await waitUntil(() => harness.adapter.getState().adapter.conversationsInspected === 1)
  harness.addConversation('conversation-visible-2', [message('item-visible-2')])
  harness.dispatchList('scroll')
  await waitUntil(() => harness.callbacks.length === 2)
  assert.equal(harness.list.scrollTop, originalScrollTop)
  harness.adapter.cancel()
})

test('folder changes cancel the active scan and stop further submissions', async () => {
  const harness = createHarness({ conversations: [{ id: 'conversation-a', messages: [message('item-a')] }] })
  assert.equal(harness.adapter.start(), true)
  await waitUntil(() => harness.callbacks.length === 1)
  harness.setFolder('/mail/sentitems/id/account')
  harness.adapter.syncFolder()
  harness.callbacks[0](null, { status: 'Safe', score: 100 })
  await new Promise((resolve) => setTimeout(resolve, 80))
  assert.equal(harness.adapter.getState().adapter.active, false)
  assert.equal(harness.submissions.length, 1)
})

test('duplicate individual message IDs are rejected and remain marked incomplete', async () => {
  const repeated = message('same-item-id')
  const harness = createHarness({ conversations: [{ id: 'conversation-duplicates', messages: [repeated, message('same-item-id')] }] })
  harness.adapter.start()
  await waitUntil(() => harness.callbacks.length === 1)
  harness.callbacks[0](null, { status: 'Safe', score: 100 })
  await waitUntil(() => harness.adapter.getState().adapter.conversationsIncomplete === 1)
  assert.deepEqual(harness.submissions, ['same-item-id'])
  harness.adapter.cancel()
})

test('failed Outlook message submissions can be retried through the shared engine', async () => {
  const harness = createHarness({ conversations: [{ id: 'conversation-retry', messages: [message('item-retry')] }] })
  harness.adapter.start()
  await waitUntil(() => harness.callbacks.length === 1)
  harness.callbacks[0](new Error('temporary network error'))
  await waitUntil(() => harness.adapter.getState().stats.failed === 1)
  assert.equal(harness.adapter.retryFailed(), true)
  await waitUntil(() => harness.callbacks.length === 2)
  harness.callbacks[1](null, { status: 'Safe', score: 100 })
  await waitUntil(() => harness.adapter.getState().stats.checked === 1)
  assert.equal(harness.submissions.length, 2)
  harness.adapter.cancel()
})

test('missing IDs and incomplete message data are skipped without API submission', async () => {
  const missingId = message('')
  const incomplete = message('item-incomplete', { body: '' })
  const harness = createHarness({ conversations: [{ id: 'conversation-incomplete', messages: [missingId, incomplete] }] })
  harness.adapter.start()
  await waitUntil(() => harness.adapter.getState().adapter.conversationsSkipped === 1)
  assert.equal(harness.submissions.length, 0)
  assert.equal(harness.adapter.getState().adapter.conversationsIncomplete, 1)
  harness.adapter.cancel()
})

test('an opened-message scan already in flight prevents a duplicate batch submission', async () => {
  const harness = createHarness({
    conversations: [{ id: 'conversation-opened', messages: [message('item-opened')] }],
    canScanMessage: () => false,
  })
  harness.adapter.start()
  await waitUntil(() => harness.adapter.getState().adapter.conversationsSkipped === 1)
  assert.equal(harness.submissions.length, 0)
  assert.equal(harness.adapter.getState().adapter.conversationsIncomplete, 1)
  harness.adapter.cancel()
})
