import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'

const source = readFileSync(new URL('./blocked.js', import.meta.url), 'utf8')
const html = readFileSync(new URL('./blocked.html', import.meta.url), 'utf8')

test('piracy policy blocked page uses caution wording without claiming confirmed malware', () => {
  const elements = new Map([
    ['block-summary', { textContent: '' }],
    ['block-warning', { textContent: '' }],
    ['score', { textContent: '' }],
  ])
  const sandbox = {
    URL,
    document: { getElementById: (id) => elements.get(id) },
  }
  const helpers = source.slice(source.indexOf('function getUrlText('), source.indexOf('function getDetailsUrl('))
  vm.runInNewContext(helpers, sandbox)

  const inferred = sandbox.inferThreatFromUrl('https://fitgirl-repacks.site/page/4')
  assert.equal(inferred.policyBlocked, true)
  assert.match(inferred.threatName, /Piracy-related content warning/)

  sandbox.applyBlockCopy({ piracyPolicyBlocked: true, score: 100 })
  assert.match(elements.get('block-summary').textContent, /blocked.*piracy-content policy/i)
  assert.match(elements.get('block-summary').textContent, /does not claim.*malware/i)
  assert.match(elements.get('score').textContent, /Caution - Blocked by policy/i)
  assert.match(elements.get('block-warning').textContent, /does not rate downloaded files/i)
  assert.match(html, /id="block-summary"/)
  assert.match(html, /id="block-warning"/)
})

test('blocked page summarizes coverage, checked links, and limitations from the scan', () => {
  const start = source.indexOf('function formatScanDetails(')
  const end = source.indexOf('\nfunction getDetailsUrl(', start)
  const sandbox = {}
  vm.runInNewContext(source.slice(start, end), sandbox)

  const details = sandbox.formatScanDetails({
    status: 'partial',
    checkedProviders: 5,
    totalProviders: 7,
    linksChecked: 1,
    totalLinks: 2,
    limitations: ['Page content and redirects were not inspected.'],
  }, ['malware-reputation'])

  assert.match(details, /Coverage: partial/)
  assert.match(details, /5\/7 providers checked/)
  assert.match(details, /1\/2 links checked/)
  assert.match(details, /malware-reputation/)
  assert.match(details, /Page content and redirects were not inspected/)
  assert.match(html, /id="scan-details"/)
  assert.match(source, /renderBlockedPage\(\{ \.\.\.context, url: blockedUrl \|\| context\.url, host: blockedHost \}\)/)
})
