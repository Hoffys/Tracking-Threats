import assert from 'node:assert/strict'
import test from 'node:test'
import vm from 'node:vm'
import { readFileSync } from 'node:fs'

const source = readFileSync(new URL('./background.js', import.meta.url), 'utf8')
test('toolbar badge distinguishes risk, caution, offline and incomplete safe checks', async () => {
  const calls = []
  const context = vm.createContext({ chrome: { action: { setBadgeText: async (value) => calls.push(value.text), setBadgeBackgroundColor: async () => {} } } })
  vm.runInContext(source.slice(source.indexOf('async function updateBadge('), source.indexOf('async function getScannerError(')), context)
  for (const [status, expected] of [
    [{ ok: false }, 'OFF'], [{ ok: true, lastStatus: 'Dangerous' }, '!'],
    [{ ok: true, lastStatus: 'Suspicious' }, '?'],
    [{ ok: true, lastStatus: 'Safe', coverage: { status: 'partial' } }, '?'],
    [{ ok: true, lastStatus: 'Safe', coverage: { status: 'complete' } }, 'OK'],
  ]) {
    context.status = status
    await vm.runInContext('updateBadge(status)', context)
    assert.equal(calls.at(-1), expected)
  }
})

test('popup live storage updates replace stale risk styles', () => {
  const popup = readFileSync(new URL('./popup.js', import.meta.url), 'utf8')
  const classes = new Set(['error'])
  const context = vm.createContext({
    pill: { textContent: '', classList: { remove: (...items) => items.forEach((item) => classes.delete(item)), add: (item) => classes.add(item) } },
    message: { textContent: '' }, openApp: {},
  })
  vm.runInContext(popup.slice(popup.indexOf('function renderStatus('), popup.indexOf("chrome.storage.local.get('threattrackStatus'")), context)
  context.status = { ok: true, lastUrl: 'https://example.com', lastStatus: 'Safe', lastScore: 100, coverage: { status: 'complete', checkedProviders: 1, totalProviders: 1 } }
  vm.runInContext('renderStatus(status)', context)
  assert.equal(classes.has('error'), false)
  assert.match(context.pill.textContent, /Appears safe/)
  context.status = { ...context.status, categories: ['piracy-content'] }
  vm.runInContext('renderStatus(status)', context)
  assert.equal(context.pill.textContent, 'CAUTION - PIRACY RISK')
  assert.doesNotMatch(context.pill.textContent, /100\/100/)
  assert.match(context.message.textContent, /URL phishing safety score 100\/100/)
  assert.match(context.message.textContent, /file was not scanned/i)
  assert.match(popup, /chrome\.storage\.onChanged\.addListener/)
})
