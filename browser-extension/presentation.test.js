import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createServer } from 'vite'
import { providerState, responseLabel, summarizeThreatIntelProviders } from '../src/utils/scanPresentation.js'

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

test('repeated link-provider checks render once without hiding different results', () => {
  const summaries = summarizeThreatIntelProviders([
    { provider: 'VirusTotal', error: 'VirusTotal returned 429' },
    { provider: 'VirusTotal', error: 'VirusTotal returned 429' },
    { provider: 'DNS Reputation', checked: true, found: false },
    { provider: 'DNS Reputation', checked: true, found: true, warning: 'Domain has no public A or AAAA DNS records' },
  ])

  assert.deepEqual(summaries, [
    { provider: 'VirusTotal', summary: 'Lookup unavailable - VirusTotal returned 429 (2 checks)' },
    { provider: 'DNS Reputation', summary: 'No match (1 of 2 checks); Matched - Domain has no public A or AAAA DNS records (1 of 2 checks)' },
  ])
})

test('public history persists detection context through JSON storage', () => {
  const source = readFileSync(new URL('../src/context/ThreatProvider.jsx', import.meta.url), 'utf8')
  const start = source.indexOf('const toPublicScanRecord =')
  const end = source.indexOf('const getDisplayDomain', start)
  const sandbox = { scan: { id: 'scan-1', type: 'URL', status: 'Safe', score: 100,
    coverage: { ...complete, status: 'partial', checkedProviders: 1, limitations: ['Missing key'] },
    categories: ['gambling-content'], categoryWarnings: ['Content category warning'],
    threatName: 'Gambling-related content warning', threatType: 'Content risk',
    confidence: 'Informational', whyDetected: ['Gambling category detected'], evidenceSources: ['Content category rules'],
    date: '2026-09-30T00:00:00.000Z' } }
  vm.runInNewContext(source.slice(start, end) + '\nglobalThis.record = toPublicScanRecord(scan)', sandbox)
  const stored = JSON.parse(JSON.stringify(sandbox.record))
  assert.deepEqual(stored.coverage, sandbox.scan.coverage)
  assert.deepEqual(stored.categories, sandbox.scan.categories)
  assert.deepEqual(stored.categoryWarnings, sandbox.scan.categoryWarnings)
  assert.equal(stored.threatName, sandbox.scan.threatName)
  assert.deepEqual(stored.whyDetected, sandbox.scan.whyDetected)
  assert.equal(stored.status, 'Safe')
})

test('rendered results distinguish incomplete checks, content categories and manual risk', async () => {
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom', logLevel: 'error' })
  try {
    const { RiskBadge } = await server.ssrLoadModule('/src/components/RiskBadge.jsx')
    const { ScanExplanation } = await server.ssrLoadModule('/src/components/ScanExplanation.jsx')
    const { ThreatIntelSummary } = await server.ssrLoadModule('/src/components/ThreatIntelSummary.jsx')
    const { EmailScanDetails } = await server.ssrLoadModule('/src/components/EmailScanDetails.jsx')
    for (const status of ['partial', 'unavailable', 'local-only', undefined]) {
      const coverage = status ? { ...complete, status, checkedProviders: 0 } : undefined
      const html = renderToStaticMarkup(createElement(RiskBadge, { risk: 'Safe', coverage }))
      assert.match(html, /Appears safe/)
      assert.match(html, /emerald/)
      const explanation = renderToStaticMarkup(createElement(ScanExplanation, { scan: { status: 'Safe', score: 100, coverage } }))
      assert.match(explanation, /Scan finished/)
      assert.match(explanation, /no further checks are pending/i)
      assert.match(explanation, /not a guarantee of safety/)
      assert.doesNotMatch(explanation, /Incomplete checks/)
    }
    assert.match(renderToStaticMarkup(createElement(RiskBadge, { risk: 'Safe', coverage: complete })), /Appears safe/)
    const piracyScan = {
      status: 'Safe', score: 100, coverage: complete,
      categories: ['piracy-content'], categoryWarnings: ['Contains piracy-related references.'],
    }
    const piracyBadge = renderToStaticMarkup(createElement(RiskBadge, { risk: 'Safe', categories: piracyScan.categories }))
    assert.match(piracyBadge, /Piracy warning - file not scanned/)
    assert.match(piracyBadge, /amber/)
    assert.doesNotMatch(piracyBadge, /Appears safe/)
    const piracyExplanation = renderToStaticMarkup(createElement(ScanExplanation, { scan: piracyScan }))
    assert.match(piracyExplanation, /file not scanned/i)
    assert.match(piracyExplanation, /URL phishing safety score: 100\/100/i)
    assert.match(piracyExplanation, /does not rate downloadable files/i)
    assert.match(piracyExplanation, /malware, fake mirrors, tampered files, and copyright risk/i)
    assert.doesNotMatch(piracyExplanation, /Appears safe based on this scan/)
    const gamblingScan = {
      status: 'Safe', score: 100, coverage: complete,
      categories: ['gambling-content'], categoryWarnings: ['Contains gambling-related references.'],
    }
    const gamblingBadge = renderToStaticMarkup(createElement(RiskBadge, { risk: 'Safe', categories: gamblingScan.categories }))
    assert.match(gamblingBadge, /Content warning - separate from phishing/)
    assert.match(gamblingBadge, /amber/)
    const gamblingExplanation = renderToStaticMarkup(createElement(ScanExplanation, { scan: gamblingScan }))
    assert.match(gamblingExplanation, /content warning found/i)
    assert.doesNotMatch(gamblingExplanation, /Appears safe based on this scan/)
    const html = renderToStaticMarkup(createElement(ScanExplanation, { manual: true, scan: {
      status: 'Dangerous', blocked: true, score: 20, coverage: { ...complete, status: 'partial', checkedProviders: 1,
        linksChecked: 2, totalLinks: 7, limitations: ['Some links were not checked.'] },
      categories: ['gambling-content', 'ip-reputation'], categoryWarnings: ['Gambling category warning'],
      threatName: 'Suspected credential phishing page', threatType: 'Phishing / credential theft',
      confidence: 'Medium', whyDetected: ['Password form submits to a different host'], evidenceSources: ['Page inspection'],
    } }))
    assert.match(html, /Why risk was detected/)
    assert.match(html, /not a calibrated probability/)
    assert.match(html, /1\/6 providers checked; 2\/7 links checked/)
    assert.match(html, /Content warnings: Gambling content/)
    assert.match(html, /Risk categories: IP reputation/)
    assert.match(html, /Gambling category warning/)
    assert.match(html, /Threat name/)
    assert.match(html, /Suspected credential phishing page/)
    assert.match(html, /Threat type/)
    assert.match(html, /Password form submits to a different host/)
    assert.match(html, /Evidence sources.*Page inspection/)
    assert.doesNotMatch(html, /Why this was blocked|confirmed phishing|Threat Blocked Automatically/)
    const intel = renderToStaticMarkup(createElement(ThreatIntelSummary, { providers: [
      { provider: 'Skipped', checked: false }, { provider: 'Failed', error: 'timeout' },
      { provider: 'Failed', error: 'timeout' },
    ] }))
    assert.doesNotMatch(intel, /No match/)
    assert.match(intel, /Not checked/)
    assert.match(intel, /Lookup unavailable - timeout \(2 checks\)/)
    assert.equal((intel.match(/Failed:/g) ?? []).length, 1)
    const emailDetails = renderToStaticMarkup(createElement(EmailScanDetails, { scan: {
      type: 'Email',
      emailDetails: { sender: 'example.org', subject: 'Subject not retained for privacy' },
      emailBreakdown: {
        sender: { status: 'Safe', score: 100, domain: 'example.org' },
        content: { status: 'Suspicious', score: 65 },
        links: { status: 'Safe', score: 100 },
      },
    } }))
    assert.match(emailDetails, /Email details/)
    assert.match(emailDetails, /example\.org/)
    assert.match(emailDetails, /Subject not retained for privacy/)
    assert.match(emailDetails, /Suspicious.*65\/100/)
    assert.match(emailDetails, /Raw email bodies are not displayed or retained in production/)
  } finally {
    await server.close()
  }
})
