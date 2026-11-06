import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'

const background = readFileSync(new URL('./background.js', import.meta.url), 'utf8')
const googleResults = readFileSync(new URL('./google-results.js', import.meta.url), 'utf8')

function loadSearchScanner({ scanFetch, getScannerError = async () => 'Search scan unavailable', readSearchMonitorConsent = async () => 'accepted' } = {}) {
  const start = background.indexOf('async function scanSearchResultUrl(')
  const end = background.indexOf('\nconst blockedDetailsRequests', start)
  assert.notEqual(start, -1)
  assert.notEqual(end, -1)
  const sandbox = {
    URL,
    Map,
    Date,
    AbortController,
    SEARCH_RESULT_SCAN_CACHE_TTL_MS: 600000,
    MAX_SEARCH_RESULT_SCAN_CACHE: 200,
    searchResultScanCache: new Map(),
    SEARCH_MONITOR_CONSENT_VERSION: '2026.10',
    API_URL: 'https://api.example/api/scan/url',
    readSearchMonitorConsent,
    isTrackableUrl: (url) => /^https:\/\//.test(url),
    syncSafeHosts: async () => {},
    getHost: (url) => new URL(url).hostname,
    isAllowedHost: () => false,
    isMarkedSafeHost: () => false,
    getScanCacheKey: (rawUrl) => {
      const url = new URL(rawUrl)
      url.hash = ''
      return url.toString()
    },
    scanFetch,
    getScannerError,
    validateUrlScanResponse: (scan) => scan,
  }
  vm.runInNewContext(`${background.slice(start, end)}\nglobalThis.scanSearchResultUrl = scanSearchResultUrl`, sandbox)
  return sandbox
}

function loadConsentHelpers(storage) {
  const start = background.indexOf('async function readSearchMonitorConsent(')
  const end = background.indexOf('\nfunction getLinkedAppUrl(', start)
  const sandbox = {
    Map,
    Date,
    SEARCH_MONITOR_CONSENT_KEY: 'trackingThreatsSearchConsent',
    SEARCH_MONITOR_CONSENT_VERSION: '2026.10',
    searchResultScanCache: new Map(),
    chrome: { storage: { local: storage } },
  }
  vm.runInNewContext(`${background.slice(start, end)}\nglobalThis.readConsent = readSearchMonitorConsent\nglobalThis.saveConsent = saveSearchMonitorConsent`, sandbox)
  return sandbox
}

const scanResult = {
  id: 'saved-scan-id', type: 'URL', status: 'Safe', score: 95,
  action: 'Allowed', blocked: false, source: 'browser-search-monitor',
}

test('Google result monitor submits a persisted authenticated URL scan with its dedicated source', async () => {
  const requests = []
  const scanner = loadSearchScanner({
    scanFetch: async (url, options) => {
      requests.push({ url, body: JSON.parse(options.body) })
      return { ok: true, json: async () => scanResult }
    },
  })

  const result = await scanner.scanSearchResultUrl('https://result.example/page', 'search-result-preview')
  assert.equal(result.id, 'saved-scan-id')
  assert.equal(requests.length, 1)
  assert.equal(requests[0].url, 'https://api.example/api/scan/url')
  assert.deepEqual(requests[0].body, {
    url: 'https://result.example/page',
    source: 'browser-search-monitor',
    reason: 'search-result-preview',
    preview: false,
    privacyAccepted: true,
    privacyNoticeVersion: '2026.10',
  })
  assert.match(background, /scanFetch\(API_URL,[\s\S]*?source: 'browser-search-preview',[\s\S]*?preview: true/)

  const controller = readFileSync(new URL('../backend/controllers/scanController.js', import.meta.url), 'utf8')
  const handler = controller.slice(controller.indexOf('export async function scanUrlHandler'), controller.indexOf('\nexport async function scanMessageHandler'))
  assert.ok(handler.indexOf('if (req.body.preview === true)') < handler.indexOf('createUrlScan(target, source'))
  assert.match(controller, /persistScan\([\s\S]*?source,[\s\S]*?clientId/)
  assert.match(background, /source: 'browser-search-monitor',[\s\S]*?privacyAccepted: true,[\s\S]*?privacyNoticeVersion: SEARCH_MONITOR_CONSENT_VERSION/)
})

test('normalized repeated search result URLs share one in-flight and cached record; distinct URLs still scan', async () => {
  const requests = []
  const scanner = loadSearchScanner({
    scanFetch: async (_url, options) => {
      requests.push(JSON.parse(options.body))
      return { ok: true, json: async () => ({ ...scanResult, id: `scan-${requests.length}` }) }
    },
  })

  const [first, repeated] = await Promise.all([
    scanner.scanSearchResultUrl('https://result.example/page?x=1#top'),
    scanner.scanSearchResultUrl('https://result.example/page?x=1#bottom'),
  ])
  assert.equal(requests.length, 1)
  assert.equal(first.id, repeated.id)
  await scanner.scanSearchResultUrl('https://other.example/page')
  assert.equal(requests.length, 2)
})

test('failed search scan requests return an unavailable result and are bounded by the retry cache', async () => {
  let calls = 0
  const scanner = loadSearchScanner({
    scanFetch: async () => { calls += 1; return { ok: false } },
    getScannerError: async () => 'Search scan unavailable: backend error',
  })
  const first = await scanner.scanSearchResultUrl('https://result.example/page')
  const repeated = await scanner.scanSearchResultUrl('https://result.example/page#again')
  assert.equal(first.ok, false)
  assert.equal(first.error, 'Search scan unavailable: backend error')
  assert.equal(repeated.ok, false)
  assert.equal(repeated.error, first.error)
  assert.equal(calls, 1)
})

test('regular navigation scan source remains browser-extension', () => {
  const scanStart = background.indexOf('async function scanUrl(')
  const previewStart = background.indexOf('\nasync function previewUrl(', scanStart)
  const navigationScanner = background.slice(scanStart, previewStart)
  assert.match(navigationScanner, /source: 'browser-extension'/)
})

test('Google results scan at most 50 distinct candidates per page session and use the persisted monitor message', () => {
  const definitions = googleResults.slice(0, googleResults.indexOf("document.addEventListener(\n  'click'"))
  const messages = []
  const sandbox = {
    URL,
    URLSearchParams,
    TRACKING_THREATS_CONFIG: { APP_URL: 'https://app.example/' },
    chrome: { runtime: { sendMessage: (message) => messages.push(message) } },
  }
  vm.runInNewContext(definitions, sandbox)
  vm.runInNewContext("searchConsentDecision = 'accepted'", sandbox)
  const candidates = Array.from({ length: 80 }, (_, index) => `https://result-${index}.example/`)
  sandbox.collectResultLinks = () => candidates
  sandbox.showSearchStatus = () => {}
  sandbox.scanGoogleResults()
  sandbox.collectResultLinks = () => candidates.concat('https://new-result.example/')
  sandbox.scanGoogleResults()

  assert.equal(messages.length, 50)
  assert.ok(messages.every((message) => message.type === 'scan-search-result-url'))
  assert.equal(new Set(messages.map((message) => message.url)).size, 50)
})

test('search candidate collection excludes links inside marked advertisement containers', () => {
  const definitions = googleResults.slice(0, googleResults.indexOf("document.addEventListener(\n  'click'"))
  const makeAnchor = (href, ad = false) => {
    const anchor = {
      matches: () => false,
      closest(selector) { return selector === 'a[href]' || ad && selector.includes('#tads') ? anchor : null },
      getAttribute: () => href,
      getBoundingClientRect: () => ({ width: 200, height: 30 }),
    }
    return anchor
  }
  const organic = makeAnchor('https://organic.example/path')
  const advertisement = makeAnchor('https://sponsor.example/offer', true)
  const sandbox = {
    URL,
    URLSearchParams,
    TRACKING_THREATS_CONFIG: { APP_URL: 'https://app.example/' },
    window: { location: { href: 'https://www.google.com/search?q=test' } },
    document: { querySelectorAll: () => [organic, advertisement] },
  }
  vm.runInNewContext(definitions, sandbox)
  assert.deepEqual(Array.from(sandbox.collectResultLinks()), ['https://organic.example/path'])
})

test('missing search consent shows the disclosure and does not start result requests', () => {
  const definitions = googleResults.slice(0, googleResults.indexOf("document.addEventListener(\n  'click'"))
  const messages = []
  const dialogs = []
  let scanCalls = 0
  const sandbox = {
    URL,
    URLSearchParams,
    TRACKING_THREATS_CONFIG: { APP_URL: 'https://app.example/' },
    window: { clearTimeout() {} },
    document: { getElementById: () => null },
    chrome: { runtime: { sendMessage: (message, callback) => {
      messages.push(message)
      if (message.type === 'get-search-monitor-consent') callback({ ok: true, decision: 'missing', noticeVersion: '2026.10' })
    } } },
  }
  vm.runInNewContext(definitions, sandbox)
  sandbox.showSearchStatus = () => {}
  sandbox.showSearchConsentDialog = (settingsMode) => dialogs.push(settingsMode)
  sandbox.collectResultLinks = () => ['https://result.example/']
  sandbox.scanGoogleResults = () => { scanCalls += 1 }
  sandbox.initializeSearchMonitoring()
  assert.deepEqual(messages.map((message) => message.type), ['get-search-monitor-consent'])
  assert.deepEqual(dialogs, [undefined])
  assert.equal(scanCalls, 0)
  assert.match(googleResults, /Saved monitoring sends eligible result URLs to the Tracking Threats backend/)
  assert.match(googleResults, /I agree to send eligible search-result URLs/)
})

test('search consent starts missing, stores each explicit preference, and invalidates stale versions', async () => {
  const values = {}
  const storage = {
    async get(key) { return { [key]: values[key] } },
    async set(update) { Object.assign(values, update) },
  }
  const helpers = loadConsentHelpers(storage)
  assert.equal(await helpers.readConsent(), 'missing')
  assert.equal(await helpers.saveConsent('saved'), 'accepted')
  assert.equal(await helpers.readConsent(), 'accepted')
  assert.equal(values.trackingThreatsSearchConsent.accepted, true)
  assert.equal(values.trackingThreatsSearchConsent.mode, 'saved')
  assert.equal(values.trackingThreatsSearchConsent.noticeVersion, '2026.10')
  assert.equal(await helpers.saveConsent('preview-only'), 'preview-only')
  assert.equal(await helpers.readConsent(), 'preview-only')
  assert.equal(values.trackingThreatsSearchConsent.accepted, false)
  assert.equal(await helpers.saveConsent('disabled'), 'disabled')
  assert.equal(await helpers.readConsent(), 'disabled')
  values.trackingThreatsSearchConsent.noticeVersion = 'old-version'
  assert.equal(await helpers.readConsent(), 'missing')
})

test('search consent UI sends a decision value compatible with the background listener', () => {
  const start = googleResults.indexOf('function saveSearchMonitoringConsent(')
  const end = googleResults.indexOf('\nfunction applySearchConsentDecision(', start)
  const sent = []
  const sandbox = {
    sendRuntimeMessage(message, callback) {
      sent.push(message)
      callback({ ok: true, decision: 'preview-only', noticeVersion: '2026.10' })
    },
    applySearchConsentDecision() {},
  }
  vm.runInNewContext(`${googleResults.slice(start, end)}\nglobalThis.savePreference = saveSearchMonitoringConsent`, sandbox)
  sandbox.savePreference('preview-only', { remove() {} })
  assert.equal(sent.length, 1)
  assert.equal(sent[0].type, 'set-search-monitor-consent')
  assert.equal(sent[0].decision, 'preview-only')
  assert.match(background, /set-search-monitor-consent' && typeof message\.decision === 'string'/)
})

test('saved, preview-only, and disabled preferences switch search monitoring safely', () => {
  const definitions = googleResults.slice(0, googleResults.indexOf("document.addEventListener(\n  'click'"))
  const sandbox = {
    URL,
    URLSearchParams,
    TRACKING_THREATS_CONFIG: { APP_URL: 'https://app.example/' },
    window: { clearTimeout() {} },
    document: { getElementById: () => null },
  }
  vm.runInNewContext(definitions, sandbox)
  let scans = 0
  sandbox.showSearchStatus = () => {}
  sandbox.showSearchConsentDialog = () => {}
  sandbox.scanGoogleResults = () => { scans += 1 }

  sandbox.applySearchConsentDecision('accepted', '2026.10')
  assert.equal(scans, 1)
  assert.equal(vm.runInNewContext('searchConsentDecision', sandbox), 'accepted')
  sandbox.applySearchConsentDecision('preview-only', '2026.10')
  assert.equal(vm.runInNewContext('searchConsentDecision', sandbox), 'preview-only')
  assert.equal(vm.runInNewContext('searchConsentGeneration', sandbox), 2)
  assert.equal(scans, 2)
  sandbox.applySearchConsentDecision('disabled', '2026.10')
  assert.equal(vm.runInNewContext('searchConsentDecision', sandbox), 'disabled')
  assert.equal(scans, 2)
  sandbox.applySearchConsentDecision('accepted', '2026.10')
  assert.equal(scans, 3)
})

test('search scans are blocked while disabled, and Gmail consent remains independent', async () => {
  let calls = 0
  const scanner = loadSearchScanner({
    readSearchMonitorConsent: async () => 'disabled',
    scanFetch: async () => { calls += 1; return { ok: true, json: async () => scanResult } },
  })
  const blocked = await scanner.scanSearchResultUrl('https://result.example/')
  assert.equal(blocked.consentRequired, true)
  assert.equal(calls, 0)
  assert.match(background, /const EMAIL_CONSENT_KEY = 'trackingThreatsEmailConsent'/)
  assert.match(background, /const EMAIL_CONSENT_VERSION = '2026\.09'/)
  assert.match(readFileSync(new URL('./email-monitor.js', import.meta.url), 'utf8'), /const EMAIL_CONSENT_VERSION = '2026\.09'/)
})

test('preview-only consent uses the existing non-persistent preview path; disabled consent sends no requests', () => {
  const definitions = googleResults.slice(0, googleResults.indexOf("document.addEventListener(\n  'click'"))
  const messages = []
  const sandbox = {
    URL,
    URLSearchParams,
    TRACKING_THREATS_CONFIG: { APP_URL: 'https://app.example/' },
    window: { clearTimeout() {} },
    document: { getElementById: () => null },
    chrome: { runtime: { sendMessage: (message) => messages.push(message) } },
  }
  vm.runInNewContext(definitions, sandbox)
  sandbox.collectResultLinks = () => ['https://result.example/']
  sandbox.showSearchStatus = () => {}
  sandbox.markSearchLinks = () => {}
  sandbox.showResultPopup = () => {}
  sandbox.applySearchConsentDecision('preview-only', '2026.10')
  assert.equal(messages.length, 1)
  assert.equal(messages[0].type, 'preview-candidate-url')
  assert.match(background, /async function previewSearchResultUrl\([\s\S]*?readSearchMonitorConsent\(\) !== 'preview-only'/)
  assert.match(background, /source: 'browser-search-preview',[\s\S]*?preview: true/)

  messages.length = 0
  sandbox.applySearchConsentDecision('disabled', '2026.10')
  assert.equal(messages.length, 0)
})
