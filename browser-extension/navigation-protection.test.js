import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'

const source = readFileSync(new URL('./background.js', import.meta.url), 'utf8')

function loadHelpers(startMarker, endMarker) {
  const start = source.indexOf(startMarker)
  const end = source.indexOf(endMarker, start)
  assert.notEqual(start, -1, `Missing helper: ${startMarker}`)
  assert.notEqual(end, -1, `Missing helper boundary: ${endMarker}`)
  const sandbox = { URL, Promise, Map, Date }
  vm.runInNewContext(source.slice(start, end), sandbox)
  return sandbox
}

test('URL scan verdicts block dangerous and policy-blocked results, while warning on suspicious', () => {
  const start = source.indexOf('function isPiracyPolicyBlocked(')
  const end = source.indexOf('\nfunction getDownloadFileName(', start)
  const sandbox = { URL }
  vm.runInNewContext(source.slice(start, end), sandbox)

  assert.equal(sandbox.isBlockedScan({ status: 'Safe', blocked: false }), false)
  assert.equal(sandbox.isBlockedScan({ status: 'Suspicious', blocked: false }), false)
  assert.equal(sandbox.isBlockedScan({ status: 'Dangerous', blocked: true }), true)
  assert.equal(sandbox.isBlockedScan({ status: 'Caution', categories: ['piracy-content'] }), true)
})

test('safe results remain normal, suspicious results get warning copy, and dangerous results show blocked copy', () => {
  const start = source.indexOf('function getScanNotification(')
  const end = source.indexOf('\nasync function notifyScanResult(', start)
  const sandbox = {
    getHost: (url) => new URL(url).hostname,
    isPiracyPolicyBlocked: (scan) => scan.categories?.includes('piracy-content') === true,
    getDetectedThreat: () => 'Phishing risk',
    getPrimaryWarning: () => 'Suspicious credential form.',
  }
  vm.runInNewContext(source.slice(start, end), sandbox)

  const safe = sandbox.getScanNotification({ status: 'Safe', score: 96 }, 'https://safe.example/')
  const suspicious = sandbox.getScanNotification({ status: 'Suspicious', score: 65 }, 'https://review.example/')
  const dangerous = sandbox.getScanNotification({ status: 'Dangerous', score: 30 }, 'https://blocked.example/')
  assert.match(safe.title, /appears safe/i)
  assert.match(suspicious.title, /caution/i)
  assert.match(suspicious.message, /Suspicious credential form/)
  assert.match(dangerous.title, /risk detected/i)
  assert.match(dangerous.message, /Phishing risk/)
})

test('navigation scan requests deduplicate concurrent work and release the key for retries', async () => {
  const sandbox = loadHelpers('function runDeduplicatedScan(', '\nfunction isBlockedScan(')
  const requests = new Map()
  let calls = 0
  let release
  const createRequest = () => {
    calls += 1
    return new Promise((resolve) => { release = resolve })
  }

  const first = sandbox.runDeduplicatedScan(requests, 'https://example.test/', createRequest)
  const second = sandbox.runDeduplicatedScan(requests, 'https://example.test/', createRequest)
  await Promise.resolve()
  assert.equal(calls, 1)
  release({ status: 'Safe' })
  assert.deepEqual(await Promise.all([first, second]), [{ status: 'Safe' }, { status: 'Safe' }])
  assert.equal(requests.size, 0)

  const retry = await sandbox.runDeduplicatedScan(requests, 'https://example.test/', async () => {
    calls += 1
    return { status: 'Suspicious' }
  })
  assert.equal(calls, 2)
  assert.equal(retry.status, 'Suspicious')
})

test('recent scan cache ignores URL fragments', () => {
  const sandbox = loadHelpers('function getScanCacheKey(', '\nfunction runDeduplicatedScan(')
  assert.equal(
    sandbox.getScanCacheKey('https://example.test/path?q=1#first'),
    sandbox.getScanCacheKey('https://example.test/path?q=1#second'),
  )
  assert.notEqual(
    sandbox.getScanCacheKey('https://example.test/path?q=1'),
    sandbox.getScanCacheKey('https://example.test/path?q=2'),
  )
})

test('dynamic host block rules cover subdomains and top-level navigations only', () => {
  const sandbox = loadHelpers('function escapeRegex(', '\nasync function syncBlockRules(')
  const rule = sandbox.getBlockRule('example.test', 10000)
  assert.equal(rule.id, 10000)
  assert.equal(rule.action.type, 'block')
  assert.deepEqual(Array.from(rule.condition.resourceTypes), ['main_frame'])
  assert.match(rule.condition.regexFilter, /example\\\.test/)
  assert.ok(rule.condition.regexFilter.includes('([^/?#]+\\.)?')) // optional subdomain prefix
})

test('startup reconciliation removes stale managed DNR rules and restores remembered hosts', async () => {
  const start = source.indexOf('async function syncBlockRules(')
  const end = source.indexOf('\nasync function clearPassThroughBlockRules(', start)
  const updates = []
  const sandbox = {
    BLOCK_RULE_ID_BASE: 10000,
    MAX_BLOCK_RULES: 250,
    blockedHosts: new Map([['danger.example', 10000]]),
    getBlockRule: (host, id) => ({ id, host }),
    chrome: {
      declarativeNetRequest: {
        getDynamicRules: async () => [{ id: 10000 }, { id: 10001 }, { id: 20001 }],
        updateDynamicRules: async (update) => updates.push(update),
      },
    },
  }
  vm.runInNewContext(source.slice(start, end), sandbox)
  await sandbox.syncBlockRules()
  assert.deepEqual(Array.from(updates[0].removeRuleIds), [10000, 10001])
  assert.deepEqual(Array.from(updates[0].addRules, (rule) => rule.host), ['danger.example'])
})

test('late dangerous verdicts do not redirect a tab that navigated to another host', async () => {
  const start = source.indexOf('async function openBlockedPageForCurrentNavigation(')
  const end = source.indexOf('\nasync function scanUrl(', start)
  const opened = []
  const sandbox = {
    Number,
    tabNavigationTargets: new Map([[4, 'https://current.example/']]),
    getScanCacheKey: (url) => {
      const parsedUrl = new URL(url)
      parsedUrl.hash = ''
      return parsedUrl.toString()
    },
    getHost: (url) => {
      try { return new URL(url).hostname.replace(/^www\./, '') } catch { return '' }
    },
    chrome: {
      runtime: { getURL: () => 'chrome-extension://id/blocked.html' },
      tabs: { get: async () => ({ id: 4, url: 'https://current.example/' }) },
    },
    openBlockedPage: (...args) => opened.push(args),
    console: { debug() {} },
  }
  vm.runInNewContext(source.slice(start, end), sandbox)
  await sandbox.openBlockedPageForCurrentNavigation(4, 'https://old.example/login', { status: 'Dangerous' })
  assert.equal(opened.length, 0)
  sandbox.tabNavigationTargets.set(4, 'https://old.example/account')
  await sandbox.openBlockedPageForCurrentNavigation(4, 'https://old.example/login', { status: 'Dangerous' })
  assert.equal(opened.length, 0)
})

test('navigation scans start at before-navigate, have a timeout, and retain blocked-page details', () => {
  assert.match(source, /webNavigation\.onBeforeNavigate\?\.addListener/)
  assert.match(source, /AbortSignal\.timeout\(12000\)/)
  assert.match(source, /tabNavigationTargets\.get\(tabId\)/)
  assert.match(source, /threat=\$\{encodeURIComponent\(\s*getDetectedThreat\(scan\)/)
  assert.match(source, /name=\$\{encodeURIComponent\(getThreatName\(scan\)\)/)
  assert.match(source, /warning=\$\{encodeURIComponent\(getPrimaryWarning\(scan\)\)/)
  assert.match(source, /score=\$\{encodeURIComponent\(/)
  assert.match(source, /scan=\$\{encodeURIComponent\(/)
})
