import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'
import { readSearchPreview } from '../src/utils/searchPreview.js'

const source = readFileSync(new URL('./google-results.js', import.meta.url), 'utf8')
const appUrl = 'https://app.example/'
const target = 'http://www.wikidata.org/entity/Q533235'
const scan = {
  status: 'Safe', score: 84,
  summary: 'Found 1 URL warning sign.',
  warningSigns: ['URL does not use HTTPS'],
  recommendations: ['Proceed with normal caution.'],
  threatName: 'Suspicious website',
  threatType: 'Website risk',
  confidence: 'Medium',
  whyDetected: ['URL does not use HTTPS'],
  evidenceSources: ['Local detection rules'],
}

function extension() {
  let reply
  const sandbox = {
    URL, URLSearchParams,
    TRACKING_THREATS_CONFIG: { APP_URL: appUrl },
    chrome: { runtime: { sendMessage: (_message, callback) => { reply = callback } } },
  }
  vm.runInNewContext(source.slice(0, source.indexOf('function addBadge(')), sandbox)
  return { ...sandbox, reply: (response) => reply(response) }
}

function popupExtension() {
  const elements = []
  const makeElement = (tagName) => {
    const node = {
      tagName,
      children: [],
      style: {},
      attributes: {},
      listeners: {},
      textContent: '',
      appendChild(child) { this.children.push(child); return child },
      append(...children) { children.forEach((child) => this.appendChild(child)) },
      setAttribute(name, value) { this.attributes[name] = value },
      addEventListener(name, listener) { this.listeners[name] = listener },
      focus() { this.focused = true },
      remove() { this.removed = true },
    }
    elements.push(node)
    return node
  }
  const sandbox = {
    URL, URLSearchParams,
    TRACKING_THREATS_CONFIG: { APP_URL: appUrl },
    document: {
      body: { appendChild(node) { this.child = node } },
      getElementById: () => null,
      createElement: makeElement,
    },
  }
  vm.runInNewContext(source.slice(0, source.indexOf('function addBadge(')), sandbox)
  return { ...sandbox, elements }
}

test('search details carry the exact displayed preview and retain the linked client', () => {
  const app = extension()
  const anchor = {}
  app.setDetailsHref(anchor, target, scan)
  assert.deepEqual(readSearchPreview(anchor.href), { target, ...scan })

  app.reply({ ok: true, appUrl: `${appUrl}?client=cl_example` })
  const url = new URL(anchor.href)
  assert.equal(url.searchParams.get('client'), 'cl_example')
  assert.equal(url.searchParams.get('page'), 'history')
  assert.equal(url.searchParams.get('preview'), '1')
  assert.equal(url.searchParams.has('blocked'), false)
  assert.equal(url.searchParams.has('scan'), false)
  assert.equal(url.search.includes('wikidata'), false)
  assert.deepEqual(readSearchPreview(url.href), { target, ...scan })
})

test('safe, suspicious and dangerous preview snapshots round trip without a saved scan ID', () => {
  const app = extension()
  for (const [status, score] of [['Safe', 84], ['Suspicious', 65], ['Dangerous', 20]]) {
    const expected = { ...scan, status, score }
    const href = app.getDetailsUrl(target, `${appUrl}?scan=old&blocked=old`, expected)
    const result = readSearchPreview(href)
    assert.deepEqual(result, { target, ...expected })
    assert.equal('id' in result, false)
    assert.equal('blocked' in result, false)
  }
})

test('invalid or missing preview data cannot masquerade as a saved history result', () => {
  assert.equal(readSearchPreview(`${appUrl}?preview=1`), null)
  assert.equal(readSearchPreview(`${appUrl}?preview=1#preview=not-json`), null)
  assert.equal(readSearchPreview(`${appUrl}?blocked=${encodeURIComponent(target)}`), null)
  for (const change of [{ target: 'javascript:alert(1)' }, { score: 101 }, { score: '84' }, { status: 'Unknown' }]) {
    const fragment = new URLSearchParams({ preview: JSON.stringify({ target, ...scan, ...change }) })
    assert.equal(readSearchPreview(`${appUrl}?preview=1#${fragment}`), null)
  }
  const fragment = new URLSearchParams({ preview: JSON.stringify({
    target, ...scan, warningSigns: [{ unexpected: true }, 'Valid warning'], recommendations: null,
  }) })
  const result = readSearchPreview(`${appUrl}?preview=1#${fragment}`)
  assert.deepEqual(result.warningSigns, ['Valid warning'])
  assert.deepEqual(result.recommendations, [])
})

test('Safety Score modal shows only triggered local rules, evidence, and unavailable providers honestly', () => {
  const app = popupExtension()
  app.showSafetyScoreModal(target, {
    status: 'Dangerous', score: 20,
    recommendations: ['Avoid this website.'],
    details: {
      findings: [
        { code: 'brand-impersonation', label: 'Possible brand impersonation', deduction: 30, evidence: { brand: 'Example', hostname: 'evil.test' } },
        { code: 'query-brand-mention', label: 'Informational mention', deduction: 0, evidence: { brand: 'Example' } },
      ],
      threatIntel: [
        { provider: 'Google Safe Browsing', checked: false, skipped: 'Not configured', found: false },
        { provider: 'URLhaus URL', checked: true, found: true, warning: 'URLhaus lists this URL' },
      ],
    },
  })
  const text = app.elements.map((element) => element.textContent).join(' ')
  assert.match(text, /Why is this website dangerous\?/)
  assert.match(text, /Possible brand impersonation/)
  assert.match(text, /Evidence found:.*Example.*evil\.test/)
  assert.match(text, /Google Safe Browsing: Unavailable/)
  assert.match(text, /URLhaus URL: Finding reported/)
  assert.doesNotMatch(text, /Informational mention/)
  assert.match(text, /Avoid this website\./)
  assert.equal(app.document.body.child.children[0].attributes['aria-modal'], 'true')
})

test('Safety Score modal explains Safe and Suspicious states and handles missing evidence', () => {
  const app = popupExtension()
  app.showSafetyScoreModal(target, { status: 'Safe', score: 94, details: { findings: [], threatIntel: [] } })
  let text = app.elements.map((element) => element.textContent).join(' ')
  assert.match(text, /Fewer risk indicators were detected/)
  assert.match(text, /No Security Findings Detected/)

  const suspiciousApp = popupExtension()
  suspiciousApp.showSafetyScoreModal(target, { status: 'Suspicious', score: 62 })
  text = suspiciousApp.elements.map((element) => element.textContent).join(' ')
  assert.match(text, /warning signs/i)
  assert.match(text, /Local security finding details are unavailable for this scan\./)
})

test('piracy content warning stays separate from a Safe URL security classification', () => {
  const app = popupExtension()
  app.showSafetyScoreModal(target, {
    status: 'Safe', score: 100,
    categories: ['piracy-content'],
    categoryWarnings: ['Contains piracy-related references; this is not a phishing determination.'],
    recommendations: ['Download risk is unknown. Scan the actual file before opening it.'],
    details: { categories: ['piracy-content'], categoryWarnings: [], findings: [], threatIntel: [] },
    threatIntel: [{ provider: 'Google Safe Browsing', checked: false, skipped: 'Not configured', found: false }],
  })
  const text = app.elements.map((element) => element.textContent).join(' ')
  assert.match(text, /URL Security Classification: Safe/)
  assert.match(text, /Piracy \/ Content Risk/)
  assert.match(text, /not a phishing determination/)
  assert.match(text, /This is a separate content\/download risk warning/)
  assert.match(text, /No Security Findings Detected/)
  assert.match(text, /Google Safe Browsing: Unavailable/)
  assert.doesNotMatch(text, /No local URL security findings were recorded/)
  assert.doesNotMatch(text, /No external provider findings were returned/)
  assert.match(text, /Download risk is unknown/)
})

test('empty and missing provider detail arrays have distinct modal messages', () => {
  const empty = popupExtension()
  empty.showSafetyScoreModal(target, { status: 'Safe', score: 100, details: { threatIntel: [] } })
  let text = empty.elements.map((element) => element.textContent).join(' ')
  assert.match(text, /No external provider findings were returned/)

  const missing = popupExtension()
  missing.showSafetyScoreModal(target, { status: 'Safe', score: 100 })
  text = missing.elements.map((element) => element.textContent).join(' ')
  assert.match(text, /Threat intelligence provider details were not included/)
})

test('unavailable providers hide technical errors while preserving no-finding status', () => {
  const app = popupExtension()
  app.showSafetyScoreModal(target, {
    status: 'Suspicious', score: 62,
    threatIntel: [
      { provider: 'PhishTank', checked: false, skipped: 'PhishTank API key is not configured', found: false },
      { provider: 'VirusTotal', checked: false, error: 'VirusTotal returned 429', found: false },
      { provider: 'URLhaus URL', checked: true, found: false },
    ],
  })
  const text = app.elements.map((element) => element.textContent).join(' ')
  assert.match(text, /PhishTank: Unavailable/)
  assert.match(text, /VirusTotal: Unavailable/)
  assert.doesNotMatch(text, /The threat intelligence check could not be completed\./)
  assert.match(text, /URLhaus URL: No finding reported/)
  assert.doesNotMatch(text, /API key is not configured|returned 429|HTTP 429/)
})

test('coverage, categories and content warnings survive linked-app preview roundtrips', () => {
  const app = extension()
  for (const status of ['complete', 'partial', 'unavailable', 'local-only']) {
    const expected = {
      ...scan,
      coverage: { status, checkedProviders: status === 'complete' ? 6 : 0, totalProviders: 6,
        linksChecked: status === 'complete' ? 2 : 0, totalLinks: 2,
        limitations: ['Provider unavailable: <script> & # + %', 'Only static URL analysis.'] },
      categories: ['gambling-content', 'ip-reputation'],
      categoryWarnings: ['Gambling category does not establish phishing.'],
    }
    const anchor = {}
    app.setDetailsHref(anchor, target, expected)
    app.reply({ ok: true, appUrl: `${appUrl}?client=cl_example` })
    assert.deepEqual(readSearchPreview(anchor.href), { target, ...expected })
    assert.equal(new URL(anchor.href).search.includes('Provider'), false)
    const style = app.getResultStyle(expected)
    assert.equal(style.label, 'CONTENT WARNING')
    assert.equal(style.background, '#fef3c7')
    assert.match(app.getCoverageText(expected), /Scan finished/)
    assert.match(app.getCoverageText(expected), /No further checks are pending/)
  }
  const piracy = { ...scan, status: 'Safe', score: 100, categories: ['piracy-content'] }
  assert.equal(app.getResultStyle(piracy).label, 'CAUTION - PIRACY RISK')
  assert.equal(app.isRiskyScan(piracy), true)
  assert.match(app.getScoreText(piracy), /URL phishing safety score: 100\/100/)
  assert.match(app.getScoreText(piracy), /Downloaded files were not scanned/)
  assert.match(source, /Blocked by the piracy-content policy/)
})

test('malformed coverage and forged category values cannot advertise complete checks', () => {
  const app = extension()
  const result = readSearchPreview(app.getDetailsUrl(target, appUrl, {
    ...scan, coverage: { status: 'complete', checkedProviders: -1, totalProviders: 6 },
    categories: ['gambling-content', {}, '__proto__', 'gambling-content'],
    categoryWarnings: [{ unexpected: true }, 'Content warning'],
  }))
  assert.equal(result.coverage, undefined)
  assert.deepEqual(result.categories, ['gambling-content'])
  assert.deepEqual(result.categoryWarnings, ['Content warning'])
  assert.equal(app.getResultStyle(result).label, 'CONTENT WARNING')
  assert.match(app.getCoverageText(result), /Check details were not recorded/)
  assert.equal(app.getResultStyle({ ...scan, status: 'Dangerous' }).label, 'RISK DETECTED')
})

test('search result dialogs stay inside the viewport and scroll their own content', () => {
  const resultPopup = source.slice(source.indexOf('function showResultPopup('), source.indexOf('function createPreviewButton('))
  const clickPreview = source.slice(source.indexOf('function showClickPreview('), source.indexOf('function scanGoogleResults('))

  for (const dialogSource of [resultPopup, clickPreview]) {
    assert.match(dialogSource, /max-height:calc\(100dvh - \d+px\)/)
    assert.match(dialogSource, /overflow-y:auto/)
    assert.match(dialogSource, /overscroll-behavior:contain/)
    assert.match(dialogSource, /-webkit-overflow-scrolling:touch/)
  }
})

test('Google result popup offers expandable scan details and keeps its app link', () => {
  const disclosureSource = source.slice(
    source.indexOf('function appendScanDetailsDisclosure('),
    source.indexOf('const MAX_RESULTS_TO_SCAN'),
  )
  const popupSource = source.slice(
    source.indexOf('function showResultPopup('),
    source.indexOf('function createPreviewButton('),
  )

  assert.match(disclosureSource, /document\.createElement\('details'\)/)
  assert.match(disclosureSource, /document\.createElement\('summary'\)/)
  assert.match(disclosureSource, /summary\.textContent = 'View more details'/)
  assert.match(popupSource, /appendScanDetailsDisclosure\(popup, topScan\)/)
  assert.match(popupSource, /details\.textContent = 'Open in Tracking Threats'/)
})

test('missing and failed preview replies produce an amber unavailable message', () => {
  const elements = new Map()
  const element = () => ({
    children: [], style: {}, textContent: '', setAttribute() {},
    addEventListener() {},
    append(...items) { this.children.push(...items) },
    appendChild(item) { this.children.push(item); if (item.id) elements.set(item.id, item) },
  })
  const callbacks = []
  const sandbox = {
    URL, URLSearchParams,
    TRACKING_THREATS_CONFIG: { APP_URL: appUrl },
    document: { getElementById: (id) => elements.get(id), createElement: element, body: element() },
    chrome: { runtime: { sendMessage: (_message, callback) => callbacks.push(callback) } },
  }
  vm.runInNewContext(source.slice(0, source.lastIndexOf('document.addEventListener(')), sandbox)
  vm.runInNewContext(`searchConsentDecision = 'accepted'; collectResultLinks = () => ['https://one.example/', 'https://two.example/']; scanGoogleResults()`, sandbox)
  assert.doesNotThrow(() => callbacks[0](undefined))
  callbacks[1]({ ok: false, error: 'Scanner offline' })
  const banner = elements.get('threattrack-search-status')
  assert.match(banner.style.cssText, /rgba\(245,158,11/)
  assert.match(banner.children.map((child) => child.textContent).join(' '), /2 unavailable/)
  assert.match(banner.children.map((child) => child.textContent).join(' '), /Could not assess/)
  assert.doesNotMatch(banner.children.map((child) => child.textContent).join(' '), /results appear safe/)
})

test('invalidated extension context in an async runtime callback is handled without changing the fallback link', () => {
  let callback
  const sandbox = {
    URL, URLSearchParams,
    TRACKING_THREATS_CONFIG: { APP_URL: appUrl },
    chrome: { runtime: { sendMessage: (_message, done) => { callback = done } } },
  }
  vm.runInNewContext(source.slice(0, source.indexOf('function addBadge(')), sandbox)
  const anchor = {}
  sandbox.setDetailsHref(anchor, target, scan)
  assert.doesNotThrow(() => {
    Object.defineProperty(sandbox.chrome.runtime, 'lastError', {
      configurable: true,
      get() { throw new Error('Extension context invalidated.') },
    })
    callback({ ok: true, appUrl: 'https://linked.example/' })
  })
  assert.equal(new URL(anchor.href).origin, new URL(appUrl).origin)
})

test('synchronous context invalidation falls back, while unrelated runtime errors still surface', () => {
  const makeSandbox = (messageError) => ({
    URL, URLSearchParams,
    TRACKING_THREATS_CONFIG: { APP_URL: appUrl },
    chrome: { runtime: { sendMessage() { throw messageError } } },
  })
  const invalidated = makeSandbox(new Error('Extension context invalidated.'))
  vm.runInNewContext(source.slice(0, source.indexOf('function addBadge(')), invalidated)
  const anchor = {}
  assert.doesNotThrow(() => invalidated.setDetailsHref(anchor, target, scan))
  assert.equal(new URL(anchor.href).origin, new URL(appUrl).origin)

  const unrelated = makeSandbox(new Error('Unexpected runtime failure'))
  vm.runInNewContext(source.slice(0, source.indexOf('function addBadge(')), unrelated)
  assert.throws(() => unrelated.setDetailsHref({}, target, scan), /Unexpected runtime failure/)
})

test('all Google result runtime messages use the guarded callback wrapper', () => {
  assert.equal((source.match(/chrome\.runtime\.sendMessage\(/g) ?? []).length, 1)
  assert.equal((source.match(/sendRuntimeMessage\(/g) ?? []).length, 5) // definition and four call sites
})
