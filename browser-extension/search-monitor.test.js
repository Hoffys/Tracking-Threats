import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'

const background = readFileSync(new URL('./background.js', import.meta.url), 'utf8')
const googleResults = readFileSync(new URL('./google-results.js', import.meta.url), 'utf8')

function loadSearchScanner({ scanFetch, getScannerError = async () => 'Search scan unavailable' } = {}) {
  const start = background.indexOf('async function scanSearchResultUrl(')
  const end = background.indexOf('\nconst blockedDetailsRequests', start)
  assert.notEqual(start, -1)
  assert.notEqual(end, -1)
  const sandbox = {
    URL,
    Map,
    Date,
    SEARCH_RESULT_SCAN_CACHE_TTL_MS: 600000,
    MAX_SEARCH_RESULT_SCAN_CACHE: 200,
    searchResultScanCache: new Map(),
    API_URL: 'https://api.example/api/scan/url',
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
  })
  assert.match(background, /scanFetch\(API_URL,[\s\S]*?source: 'browser-search-preview',[\s\S]*?preview: true/)

  const controller = readFileSync(new URL('../backend/controllers/scanController.js', import.meta.url), 'utf8')
  const handler = controller.slice(controller.indexOf('export async function scanUrlHandler'), controller.indexOf('\nexport async function scanMessageHandler'))
  assert.ok(handler.indexOf('if (req.body.preview === true)') < handler.indexOf('createUrlScan(target, source'))
  assert.match(controller, /persistScan\([\s\S]*?source,[\s\S]*?clientId/)
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
