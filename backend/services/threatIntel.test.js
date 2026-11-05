import assert from 'node:assert/strict'
import test from 'node:test'
import { combineUrlReputation, hasVirusTotalDetections, parseProviderFlag, parseUrlhausHostResponse, runProviderChecks } from './threatIntel.js'
import { scanUrl } from './urlScanner.js'

test('parseProviderFlag accepts explicit provider truth values', () => {
  for (const value of [true, 1, '1', 'true', 'TRUE', 'y', 'Y', 'yes']) {
    assert.equal(parseProviderFlag(value), true)
  }
})

test('parseProviderFlag rejects false-like and unknown values', () => {
  for (const value of [false, 0, null, undefined, '', '0', 'false', 'n', 'no']) {
    assert.equal(parseProviderFlag(value), false)
  }
})

test('VirusTotal requires an actual malicious or suspicious detection', () => {
  assert.equal(hasVirusTotalDetections({ harmless: 72, malicious: 0, suspicious: 0 }), false)
  assert.equal(hasVirusTotalDetections({ malicious: 1, suspicious: 0 }), true)
  assert.equal(hasVirusTotalDetections({ malicious: 0, suspicious: 2 }), true)
})

test('URLhaus host history on example.com remains informational for an unrelated URL', () => {
  const result = parseUrlhausHostResponse('example.com', {
    query_status: 'ok',
    url_count: '4',
    urls: [{ url: 'http://example.com/old-payload.exe', url_status: 'offline' }],
  })
  assert.equal(result.found, true)
  assert.equal(result.urlCount, 4)
  assert.equal(result.activeUrlCount, 0)
  assert.equal(result.historicalUrlCount, 1)
  assert.equal(result.deduction, 0)
  assert.equal(result.riskAffecting, false)
  assert.equal(result.evidenceType, 'historical-host-association')
  assert.match(result.warning, /historical host evidence.*exact URL was not confirmed/i)

  const scan = combineUrlReputation(scanUrl('https://example.com/'), [result])
  assert.equal(scan.status, 'Safe')
  assert.equal(scan.score, 100)
  assert.equal(scan.action, 'Allowed')
  assert.deepEqual(scan.warningSigns, [])
  assert.equal(scan.details.threatIntel[0].warning, result.warning)
  assert.equal(scan.details.categories.includes('malware-reputation'), false)
})

test('an exact-host URLhaus match is cautionary; an exact URL match remains dangerous', () => {
  const hostMatch = parseUrlhausHostResponse('example.com', {
    query_status: 'ok',
    url_count: '1',
    urls: [{ url: 'https://example.com/other-path.exe', url_status: 'online' }],
  })
  const hostScan = combineUrlReputation(scanUrl('https://example.com/'), [hostMatch])
  assert.equal(hostScan.status, 'Suspicious')
  assert.equal(hostScan.score, 75)
  assert.equal(hostScan.action, 'Review')
  assert.equal(hostMatch.riskAffecting, true)
  assert.equal(hostMatch.deduction, 25)

  const exactUrlScan = combineUrlReputation(scanUrl('https://example.com/other-path.exe'), [{
    provider: 'URLhaus URL', checked: true, found: true,
    warning: 'URLhaus lists this exact URL for malware distribution', deduction: 65,
  }])
  assert.equal(exactUrlScan.status, 'Dangerous')
  assert.equal(exactUrlScan.action, 'Blocked')
})

test('VirusTotal rate limits remain unavailable and do not create threat evidence', async () => {
  const providers = await runProviderChecks([{
    provider: 'VirusTotal',
    run: () => { throw new Error('VirusTotal returned 429') },
  }])
  const scan = combineUrlReputation(scanUrl('https://example.com/'), providers)

  assert.equal(providers[0].checked, false)
  assert.match(providers[0].error, /429/)
  assert.equal(providers[0].found, undefined)
  assert.equal(scan.status, 'Safe')
  assert.equal(scan.score, 100)
  assert.deepEqual(scan.warningSigns, [])
})

test('URLhaus host matching is exact across www, sibling domains and subdomains', () => {
  const entry = { url: 'https://example.com/payload.exe', url_status: 'online' }
  assert.throws(() => parseUrlhausHostResponse('www.example.com', {
    query_status: 'ok', url_count: '1', urls: [entry],
  }), /did not match the queried host/)
  assert.throws(() => parseUrlhausHostResponse('badexample.com', {
    query_status: 'ok', url_count: '1', urls: [entry],
  }), /did not match the queried host/)
  assert.throws(() => parseUrlhausHostResponse('sub.example.com', {
    query_status: 'ok', url_count: '1', urls: [entry],
  }), /did not match the queried host/)
})

test('malformed URLhaus host responses never become threat matches', () => {
  for (const payload of [
    null,
    { query_status: 'ok', url_count: '1' },
    { query_status: 'unknown', urls: [] },
    { query_status: 'ok', urls: [null] },
    { query_status: 'ok', urls: [{ url: 'javascript:alert(1)', url_status: 'online' }] },
    { query_status: 'ok', url_count: '2', urls: [] },
  ]) {
    assert.throws(() => parseUrlhausHostResponse('example.com', payload))
  }
  assert.equal(parseUrlhausHostResponse('example.com', { query_status: 'no_results' }).found, false)
})
