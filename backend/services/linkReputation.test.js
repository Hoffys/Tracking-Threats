import assert from 'node:assert/strict'
import test from 'node:test'
import { scanMessage } from './messageScanner.js'
import { analyzeEmail } from './emailAnalyzer.js'
import { enrichContentLinks, maxReputationLinks } from './linkReputation.js'
import { combineUrlReputation, runProviderChecks } from './threatIntel.js'
import { scanUrl } from './urlScanner.js'

const malicious = { provider: 'PhishTank', checked: true, found: true, warning: 'Verified phishing match', deduction: 60 }
const clean = { provider: 'PhishTank', checked: true, found: false }

test('provider failures and skipped lookups remain unknown, never threat matches', async () => {
  const results = await runProviderChecks([
    { provider: 'disabled', run: () => null },
    { provider: 'limited', run: () => { throw new Error('429 rate limit') } },
    { provider: 'working', run: () => clean },
  ])
  const result = combineUrlReputation(scanUrl('https://example.com'), results)
  assert.equal(result.details.coverage.status, 'partial')
  assert.equal(result.details.coverage.checkedProviders, 1)
  assert.equal(result.details.coverage.totalProviders, 3)
  assert.equal(result.score, scanUrl('https://example.com').score)
  assert.deepEqual(result.warningSigns, scanUrl('https://example.com').warningSigns)
})

test('known phishing evidence remains dangerous when other providers fail', () => {
  const result = combineUrlReputation(scanUrl('https://example.com'), [malicious, { provider: 'other', checked: false, error: 'offline' }])
  assert.equal(result.status, 'Dangerous')
  assert.equal(result.details.coverage.status, 'partial')
  assert.ok(result.details.categories.includes('phishing-indicators'))
})

test('email and SMS inherit dangerous embedded-link reputation without averaging it away', async () => {
  for (const [text, base] of [
    ['Read https://example.com/info', scanMessage('Read https://example.com/info')],
    ['Read https://example.com/info', analyzeEmail({ sender: 'person@example.org', subject: 'Hello', body: 'Read https://example.com/info' })],
  ]) {
    const result = await enrichContentLinks(text, base, async (_url, local) => combineUrlReputation(local, [malicious]))
    assert.equal(result.status, 'Dangerous')
    assert.ok(result.score <= 40)
    assert.equal(result.details.coverage.linksChecked, 1)
    assert.ok(result.warningSigns.some((warning) => warning.includes('Verified phishing match')))
  }
})

test('links are deduplicated, bounded, and no more than two lookups run concurrently', async () => {
  const links = Array.from({ length: maxReputationLinks + 2 }, (_, index) => `https://example.com/page/${index}`)
  const text = [...links, links[0]].join(' ')
  let active = 0
  let peak = 0
  const calls = []
  const result = await enrichContentLinks(text, scanMessage(text), async (url, local) => {
    calls.push(url)
    active += 1
    peak = Math.max(peak, active)
    await new Promise((resolve) => setImmediate(resolve))
    active -= 1
    return combineUrlReputation(local, [clean])
  })
  assert.equal(calls.length, maxReputationLinks)
  assert.ok(peak <= 2)
  assert.equal(result.details.coverage.status, 'partial')
  assert.equal(result.details.coverage.totalLinks, links.length)
})

test('messages without links do not call providers and report local-only coverage', async () => {
  let calls = 0
  const result = await enrichContentLinks('Meet tomorrow', scanMessage('Meet tomorrow'), () => { calls += 1 })
  assert.equal(calls, 0)
  assert.equal(result.details.coverage.status, 'local-only')
})

test('an embedded-link outage yields incomplete coverage, not a fabricated match', async () => {
  const text = 'See https://example.com'
  const result = await enrichContentLinks(text, scanMessage(text), async () => { throw new Error('offline') })
  assert.equal(result.details.coverage.status, 'unavailable')
  assert.equal(result.details.threatIntel[0].checked, false)
  assert.equal(result.details.categories.includes('malware-reputation'), false)
})
