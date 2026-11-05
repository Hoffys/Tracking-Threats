import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'

const source = readFileSync(new URL('./background.js', import.meta.url), 'utf8')

function evaluate(start, end, additions = {}) {
  const from = source.indexOf(start)
  const to = source.indexOf(end, from)
  assert.notEqual(from, -1)
  assert.notEqual(to, -1)
  const sandbox = { URL, Promise, Map, Set, Date, Number, Array, Error, console: { warn() {}, debug() {} }, ...additions }
  vm.runInNewContext(source.slice(from, to), sandbox)
  return sandbox
}

test('URL verdict validation rejects malformed, incomplete, unrecognized, and contradictory responses', () => {
  const sandbox = evaluate('function validateUrlScanResponse(', '\nfunction noteScanFailure(')
  for (const invalid of [
    null,
    { ok: false, status: 'Safe', score: 100, action: 'Allowed', blocked: false },
    { status: 'Unknown', score: 100, action: 'Allowed', blocked: false },
    { status: 'Safe', action: 'Allowed', blocked: false },
    { status: 'Safe', score: 100, action: 'Allowed' },
    { status: 'Safe', score: 100, action: 'Blocked', blocked: true },
    { status: 'Safe', score: 100, action: 'Allowed', blocked: true },
    { status: 'Dangerous', score: 10, action: 'Allowed', blocked: false },
  ]) assert.throws(() => sandbox.validateUrlScanResponse(invalid), /Scan unavailable/)

  const safe = { status: 'Safe', score: 100, action: 'Allowed', blocked: false }
  assert.equal(sandbox.validateUrlScanResponse(safe), safe)
  const piracy = { status: 'Safe', score: 100, action: 'Allowed', blocked: true, categories: ['piracy-content'] }
  assert.equal(sandbox.validateUrlScanResponse(piracy), piracy)
})

test('pass-through hosts match exact service hosts and only intentional mail.com subdomains', () => {
  const start = source.indexOf('const PASS_THROUGH_HOSTS = new Set([')
  const end = source.indexOf('\nconst recentScans = new Map()', start)
  const sandbox = { Set }
  vm.runInNewContext(`${source.slice(start, end)}\nglobalThis.PASS_THROUGH_HOSTS = PASS_THROUGH_HOSTS`, sandbox)
  const matcher = evaluate('function isPassThroughHost(', '\nfunction isMarkedSafeHost(', {
    PASS_THROUGH_HOSTS: sandbox.PASS_THROUGH_HOSTS,
    normalizeHost: (host) => host.toLowerCase().replace(/^www\./, '').replace(/\.$/, ''),
  })
  assert.equal(matcher.isPassThroughHost('www.google.com'), true)
  assert.equal(matcher.isPassThroughHost('mail.google.com'), true)
  assert.equal(matcher.isPassThroughHost('mail.proton.me'), true)
  assert.equal(matcher.isPassThroughHost('inbox.mail.com'), true)
  assert.equal(matcher.isPassThroughHost('evilgoogle.com'), false)
  assert.equal(matcher.isPassThroughHost('notgoogle.com'), false)
  assert.equal(matcher.isPassThroughHost('google.com.attacker.test'), false)
  assert.equal(matcher.isPassThroughHost('foo.github.com'), false)
})

test('safe-host exemptions are exact-host only', () => {
  const sandbox = evaluate('function isMarkedSafeHost(', '\nfunction getNextRuleId(', {
    normalizeHost: (host) => host.toLowerCase().replace(/^www\./, '').replace(/\.$/, ''),
    safeHosts: new Set(['example.com']), allowedHosts: new Set(['trusted.test']),
  })
  assert.equal(sandbox.isMarkedSafeHost('example.com'), true)
  assert.equal(sandbox.isMarkedSafeHost('sub.example.com'), false)
  assert.equal(sandbox.isAllowedHost('trusted.test'), true)
  assert.equal(sandbox.isAllowedHost('child.trusted.test'), false)
})

test('navigation versions reject stale same-tab result but keep independent tabs current', async () => {
  const opened = []
  const sandbox = evaluate('async function openBlockedPageForCurrentNavigation(', '\nasync function scanUrl(', {
    Number,
    tabNavigationTargets: new Map([[1, 'https://same.test/new'], [2, 'https://danger.test/']]),
    tabNavigationVersions: new Map([[1, 8], [2, 3]]),
    getScanCacheKey: (url) => new URL(url).toString(),
    getHost: (url) => new URL(url).hostname,
    chrome: { runtime: { getURL: () => 'chrome-extension://id/blocked.html' }, tabs: { get: async () => ({ url: 'https://danger.test/' }) } },
    openBlockedPage: (...args) => opened.push(args),
  })
  await sandbox.openBlockedPageForCurrentNavigation(1, 'https://same.test/old', {}, 7)
  await sandbox.openBlockedPageForCurrentNavigation(2, 'https://danger.test/', {}, 3)
  assert.equal(opened.length, 1)
  assert.equal(opened[0][0], 2)
})

test('blocked-host restoration ignores duplicate IDs and enforces 250-rule capacity', async () => {
  const stored = Array.from({ length: 260 }, (_, index) => [`host${index}.test`, 10000 + (index % 250)])
  const sandbox = evaluate('async function loadBlockedHosts(', '\nasync function saveBlockedHosts(', {
    BLOCK_RULE_ID_BASE: 10000, MAX_BLOCK_RULES: 250,
    normalizeHost: (host) => host.toLowerCase(),
    chrome: { storage: { local: { get: async () => ({ blockedHosts: stored }) } } },
  })
  await sandbox.loadBlockedHosts()
  assert.equal(sandbox.blockedHosts.size, 250)
  assert.equal(new Set(sandbox.blockedHosts.values()).size, 250)
  const capacity = evaluate('function getNextRuleId(', '\nfunction escapeRegex(', {
    BLOCK_RULE_ID_BASE: 10000, MAX_BLOCK_RULES: 250,
    blockedHosts: new Map(Array.from({ length: 250 }, (_, index) => [`host${index}.test`, 10000 + index])),
  })
  assert.equal(capacity.getNextRuleId(), null)
})

test('repeated backend failures apply capped exponential retry backoff and success resets it', () => {
  let now = 1000
  class FakeDate extends Date { static now() { return now } }
  const sandbox = evaluate('function noteScanFailure(', '\nfunction getNextRuleId(', {
    Date: FakeDate, scanFailureCount: 0, scanRetryAfter: 0,
    FAILURE_BACKOFF_BASE_MS: 5000, FAILURE_BACKOFF_MAX_MS: 30000,
  })
  sandbox.noteScanFailure()
  assert.equal(sandbox.scanRetryAfter, now + 5000)
  now += 5000
  sandbox.noteScanFailure()
  assert.equal(sandbox.scanRetryAfter, now + 10000)
  for (let i = 0; i < 8; i += 1) sandbox.noteScanFailure()
  assert.equal(sandbox.scanRetryAfter, now + 30000)
  sandbox.noteScanSuccess()
  assert.equal(sandbox.scanFailureCount, 0)
  assert.equal(sandbox.scanRetryAfter, 0)
})
