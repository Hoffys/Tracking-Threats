import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createServer } from 'vite'
import { providerState, responseLabel } from '../src/utils/scanPresentation.js'

const complete = { status: 'complete', checkedProviders: 6, totalProviders: 6, limitations: [] }

test('unchecked, skipped and failed providers never render as No match', () => {
  for (const provider of [{ checked: false }, { skipped: true }, { status: 'skipped' },
    { error: 'timeout' }, { checked: true, error: 'timeout', found: true }, {}]) {
    assert.notEqual(providerState(provider), 'No match')
    assert.notEqual(providerState(provider), 'Matched')
  }
  assert.equal(providerState({ checked: true, found: false }), 'No match')
  assert.equal(providerState({ checked: true, found: true }), 'Matched')
  assert.equal(responseLabel({ status: 'Dangerous', blocked: true }, true), 'Risk detected; review recommended')
})

test('public history persists detection context through JSON storage', () => {
  const source = readFileSync(new URL('../src/context/ThreatProvider.jsx', import.meta.url), 'utf8')
  const start = source.indexOf('const toPublicScanRecord =')
  const end = source.indexOf('const getDisplayDomain', start)
  const sandbox = { scan: { id: 'scan-1', type: 'URL', status: 'Safe', score: 100,
    coverage: { ...complete, status: 'partial', checkedProviders: 1, limitations: ['Missing key'] },
    categories: ['gambling-content'], categoryWarnings: ['Content category warning'],
    date: '2026-09-30T00:00:00.000Z' } }
  vm.runInNewContext(source.slice(start, end) + '\nglobalThis.record = toPublicScanRecord(scan)', sandbox)
  const stored = JSON.parse(JSON.stringify(sandbox.record))
  assert.deepEqual(stored.coverage, sandbox.scan.coverage)
  assert.deepEqual(stored.categories, sandbox.scan.categories)
  assert.deepEqual(stored.categoryWarnings, sandbox.scan.categoryWarnings)
  assert.equal(stored.status, 'Safe')
})

test('rendered results distinguish incomplete checks, content categories and manual risk', async () => {
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom', logLevel: 'error' })
  try {
    const { RiskBadge } = await server.ssrLoadModule('/src/components/RiskBadge.jsx')
    const { ScanExplanation } = await server.ssrLoadModule('/src/components/ScanExplanation.jsx')
    const { ThreatIntelSummary } = await server.ssrLoadModule('/src/components/ThreatIntelSummary.jsx')
    for (const status of ['partial', 'unavailable', 'local-only', undefined]) {
      const coverage = status ? { ...complete, status, checkedProviders: 0 } : undefined
      const html = renderToStaticMarkup(createElement(RiskBadge, { risk: 'Safe', coverage }))
      assert.match(html, /Incomplete checks/)
      assert.doesNotMatch(html, /emerald/)
    }
    assert.match(renderToStaticMarkup(createElement(RiskBadge, { risk: 'Safe', coverage: complete })), /No strong indicators/)
    const html = renderToStaticMarkup(createElement(ScanExplanation, { manual: true, scan: {
      status: 'Dangerous', blocked: true, score: 20, coverage: { ...complete, status: 'partial', checkedProviders: 1,
        linksChecked: 2, totalLinks: 7, limitations: ['Some links were not checked.'] },
      categories: ['gambling-content', 'ip-reputation'], categoryWarnings: ['Gambling category warning'],
    } }))
    assert.match(html, /Why risk was detected/)
    assert.match(html, /not a calibrated probability/)
    assert.match(html, /1\/6 providers checked; 2\/7 links checked/)
    assert.match(html, /Content warnings: Gambling content/)
    assert.match(html, /Risk categories: IP reputation/)
    assert.match(html, /Gambling category warning/)
    assert.doesNotMatch(html, /Why this was blocked|confirmed phishing|Threat Blocked Automatically/)
    const intel = renderToStaticMarkup(createElement(ThreatIntelSummary, { providers: [
      { provider: 'Skipped', checked: false }, { provider: 'Failed', error: 'timeout' },
    ] }))
    assert.doesNotMatch(intel, /No match/)
    assert.match(intel, /Not checked/)
    assert.match(intel, /Lookup unavailable/)
  } finally {
    await server.close()
  }
})
