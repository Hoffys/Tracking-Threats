const MAX_RESULTS_TO_SCAN = 50
const GOOGLE_REDIRECT_PATHS = new Set(['/url', '/interstitial'])
const SEARCH_ENGINE_HOSTS = [
  'google.com',
  'bing.com',
  'duckduckgo.com',
  'ecosia.org',
  'search.brave.com',
  'search.yahoo.com',
  'startpage.com',
  'yahoo.com',
  'yandex.com',
]
const SEARCH_RESULT_SELECTORS = [
  'a[href] h3',
  '[data-testid="result-title-a"]',
  '.result__title a[href]',
  '.b_algo h2 a[href]',
  '.algo h3 a[href]',
  'a[href][data-testid*="result"]',
  'main a[href]',
]
const RESULT_CONTAINER_SELECTORS = [
  'article',
  '.b_algo',
  '.g',
  '.result',
  '[data-testid*="result"]',
  'li',
  'div',
]
const APP_URL = TRACKING_THREATS_CONFIG.APP_URL
const scannedResults = new Map()
const riskyResults = new Map()
const latestResults = new Map()
const scanStats = {
  checked: 0,
  safe: 0,
  caution: 0,
  dangerous: 0,
}
let scanTimer = null

function isSearchEngineHost(hostname) {
  return SEARCH_ENGINE_HOSTS.some((host) => hostname === host || hostname.endsWith(`.${host}`))
}

function isVisible(element) {
  const rect = element.getBoundingClientRect()
  return rect.width > 0 && rect.height > 0
}

function normalizeCandidate(rawHref) {
  try {
    const url = new URL(rawHref, window.location.href)
    if (url.hostname.endsWith('google.com') && GOOGLE_REDIRECT_PATHS.has(url.pathname)) {
      const redirected = url.searchParams.get('q') ?? url.searchParams.get('url')
      return redirected ? normalizeCandidate(redirected) : null
    }

    if (!['http:', 'https:'].includes(url.protocol)) return null
    if (isSearchEngineHost(url.hostname)) return null
    return url.href
  } catch {
    return null
  }
}

function collectResultLinks() {
  const candidates = []
  const seen = new Set()

  document.querySelectorAll(SEARCH_RESULT_SELECTORS.join(',')).forEach((element) => {
    const anchor = element.matches('a[href]') ? element : element.closest('a[href]')
    if (!anchor || !isVisible(anchor)) return
    const href = anchor.getAttribute('href')
    const normalized = href ? normalizeCandidate(href) : null
    if (!normalized || seen.has(normalized)) return
    seen.add(normalized)
    candidates.push(normalized)
  })

  return candidates.slice(0, MAX_RESULTS_TO_SCAN)
}

function isRiskyScan(scan) {
  return scan?.status === 'Dangerous' || scan?.status === 'Suspicious' || scan?.blocked
}

function getScanLevel(scan) {
  if (scan?.status === 'Dangerous' || scan?.blocked) return 'dangerous'
  if (scan?.status === 'Suspicious') return 'caution'
  return 'safe'
}

function getResultStyle(scan) {
  const level = getScanLevel(scan)
  if (level === 'dangerous') {
    return {
      label: 'DANGER',
      border: 'rgba(225,29,72,.5)',
      background: '#ffe4e6',
      color: '#9f1239',
      rowBackground: 'rgba(225,29,72,.12)',
    }
  }
  if (level === 'caution') {
    return {
      label: 'CAUTION',
      border: 'rgba(245,158,11,.55)',
      background: '#fef3c7',
      color: '#92400e',
      rowBackground: 'rgba(245,158,11,.12)',
    }
  }
  return {
    label: 'SAFE',
    border: 'rgba(16,185,129,.45)',
    background: '#ccfbf1',
    color: '#115e59',
    rowBackground: 'rgba(16,185,129,.08)',
  }
}

function getDetailsUrl(url, appUrl = APP_URL) {
  const detailsUrl = new URL(APP_URL)
  detailsUrl.href = appUrl
  detailsUrl.searchParams.set('page', 'history')
  detailsUrl.searchParams.set('blocked', url)
  return detailsUrl.toString()
}

function setDetailsHref(anchor, url) {
  anchor.href = getDetailsUrl(url)
  chrome.runtime.sendMessage({ type: 'get-linked-app-url' }, (response) => {
    if (chrome.runtime.lastError || !response?.ok || !response.appUrl) return
    anchor.href = getDetailsUrl(url, response.appUrl)
  })
}

function addBadge(anchor, scan) {
  if (anchor.dataset.threattrackMarked === 'true') return false

  anchor.dataset.threattrackMarked = 'true'
  anchor.dataset.threattrackStatus = scan.status

  const style = getResultStyle(scan)
  const badge = document.createElement('span')
  badge.className = 'threattrack-result-badge'
  badge.textContent = `${style.label} ${scan.score}/100`
  badge.style.cssText = [
    'all:initial',
    'box-sizing:border-box',
    'display:inline-flex',
    'align-items:center',
    'justify-content:center',
    'flex:0 0 auto',
    'align-self:flex-start',
    'width:auto',
    'min-width:0',
    'height:20px',
    'min-height:20px',
    'max-height:20px',
    'margin-left:8px',
    `border:1px solid ${style.border}`,
    'border-radius:999px',
    `background:${style.background}`,
    `color:${style.color}`,
    'font:700 11px/20px Arial,sans-serif',
    'padding:0 8px',
    'white-space:nowrap',
    'text-decoration:none',
    'vertical-align:middle',
    'cursor:pointer',
  ].join(';')
  badge.onclick = (event) => {
    event.preventDefault()
    event.stopPropagation()
    const normalized = normalizeCandidate(anchor.getAttribute('href'))
    if (!normalized) return
    chrome.runtime.sendMessage({ type: 'get-linked-app-url' }, (response) => {
      const appUrl =
        chrome.runtime.lastError || !response?.ok || !response.appUrl ? APP_URL : response.appUrl
      window.open(getDetailsUrl(normalized, appUrl), '_blank', 'noopener,noreferrer')
    })
  }

  const title = anchor.querySelector('h3')
  if (title) {
    title.appendChild(badge)
  } else {
    anchor.insertAdjacentElement('afterend', badge)
  }

  return true
}

function highlightResultContainer(anchor, scan) {
  const style = getResultStyle(scan)
  const container =
    RESULT_CONTAINER_SELECTORS.map((selector) => anchor.closest(selector)).find(Boolean) ?? anchor
  container.style.boxShadow = `inset 4px 0 0 ${style.color}`
  container.style.backgroundColor = style.rowBackground
  container.style.borderRadius = '8px'
}

function markSearchLinks(url, scan) {
  const anchors = Array.from(document.querySelectorAll('a[href]')).filter(
    (anchor) => normalizeCandidate(anchor.getAttribute('href')) === url,
  )
  const titleAnchors = anchors.filter((anchor) => anchor.querySelector('h3'))
  const textAnchors = anchors.filter(
    (anchor) =>
      !anchor.querySelector('img') &&
      anchor.textContent.trim().length > 12 &&
      anchor.getBoundingClientRect().width > 80,
  )

  if (titleAnchors.length > 0) {
    titleAnchors.forEach((anchor) => {
      addBadge(anchor, scan)
      highlightResultContainer(anchor, scan)
    })
    return
  }

  if (textAnchors.length > 0) {
    textAnchors.forEach((anchor) => {
      addBadge(anchor, scan)
      highlightResultContainer(anchor, scan)
    })
  }
}

function showSearchStatus() {
  const existing = document.getElementById('threattrack-search-status')
  const banner = existing ?? document.createElement('aside')
  const riskyCount = scanStats.caution + scanStats.dangerous
  const hasRisk = riskyCount > 0
  const accentColor = scanStats.dangerous > 0 ? '#fecdd3' : hasRisk ? '#fde68a' : '#6ee7b7'
  const borderColor =
    scanStats.dangerous > 0
      ? 'rgba(225,29,72,.45)'
      : hasRisk
        ? 'rgba(245,158,11,.45)'
        : 'rgba(16,185,129,.45)'
  const statusText =
    scanStats.checked === 0
      ? 'Scanning visible search results...'
      : hasRisk
        ? `${riskyCount} risky search result${riskyCount === 1 ? '' : 's'} found`
        : 'No risky result found in visible search results'

  banner.id = 'threattrack-search-status'
  banner.style.cssText = [
    'position:fixed',
    'right:20px',
    'top:92px',
    'z-index:2147483646',
    'box-sizing:border-box',
    'width:min(350px,calc(100vw - 32px))',
    `border:1px solid ${borderColor}`,
    'border-radius:8px',
    'background:#111827',
    'color:#f8fafc',
    'box-shadow:0 18px 50px rgba(0,0,0,.32)',
    'font:13px/1.45 Arial,sans-serif',
    'padding:12px',
  ].join(';')

  banner.innerHTML = ''

  const title = document.createElement('strong')
  title.textContent = 'Tracking Threats Search Monitor'
  title.style.cssText = `display:block;font-size:14px;color:${accentColor}`

  const body = document.createElement('p')
  body.textContent = statusText
  body.style.cssText = 'margin:6px 0 0;color:#cbd5e1'

  const counts = document.createElement('p')
  counts.textContent = `${scanStats.checked} checked - ${scanStats.safe} safe - ${scanStats.caution} caution - ${scanStats.dangerous} risk`
  counts.style.cssText = 'margin:8px 0 0;color:#e2e8f0;font-weight:700'

  banner.append(title, body, counts)
  if (!existing) document.body.appendChild(banner)
}

function showResultPopup(url, scan) {
  const existing = document.getElementById('threattrack-google-warning')
  const results = Array.from(latestResults.entries())
  const topUrl = url || results[0]?.[0]
  const topScan = scan || results[0]?.[1]
  if (!topUrl || !topScan) return

  const warningSigns = topScan.warningSigns?.slice(0, 3) ?? []
  const recommendations = topScan.recommendations?.slice(0, 2) ?? []
  const popup = existing ?? document.createElement('aside')
  const isSafe = topScan.status === 'Safe'
  const isDangerous = topScan.status === 'Dangerous' || topScan.blocked
  const borderColor = isDangerous
    ? 'rgba(225,29,72,.45)'
    : isSafe
      ? 'rgba(16,185,129,.45)'
      : 'rgba(245,158,11,.45)'
  const accentColor = isDangerous ? '#fecdd3' : isSafe ? '#6ee7b7' : '#fde68a'
  const buttonColor = isDangerous ? '#9f1239' : isSafe ? '#065f46' : '#92400e'
  const statusText = isDangerous ? 'Danger risk' : isSafe ? 'Safe result' : 'Caution'

  popup.id = 'threattrack-google-warning'
  popup.style.cssText = [
    'position:fixed',
    'right:20px',
    'top:92px',
    'z-index:2147483647',
    'box-sizing:border-box',
    'width:min(360px,calc(100vw - 32px))',
    `border:1px solid ${borderColor}`,
    'border-radius:8px',
    'background:#111827',
    'color:#f8fafc',
    'box-shadow:0 18px 50px rgba(0,0,0,.42)',
    'font:13px/1.45 Arial,sans-serif',
    'padding:14px',
  ].join(';')

  popup.innerHTML = ''

  const header = document.createElement('div')
  header.style.cssText = 'display:flex;align-items:start;justify-content:space-between;gap:12px'

  const title = document.createElement('div')
  title.innerHTML = `<strong style="display:block;font-size:14px;color:${accentColor}">Tracking Threats Result</strong><span style="color:#cbd5e1">${statusText} detected before opening this result.</span>`

  const close = document.createElement('button')
  close.type = 'button'
  close.textContent = 'x'
  close.setAttribute('aria-label', 'Dismiss warning')
  close.style.cssText = [
    'border:0',
    'border-radius:6px',
    'background:rgba(255,255,255,.08)',
    'color:#fff',
    'cursor:pointer',
    'font:700 14px Arial,sans-serif',
    'height:26px',
    'width:26px',
  ].join(';')
  close.addEventListener('click', () => popup.remove())

  header.append(title, close)
  popup.appendChild(header)

  const urlText = document.createElement('p')
  urlText.textContent = topUrl
  urlText.style.cssText = 'margin:10px 0 0;color:#e2e8f0;overflow-wrap:anywhere'
  popup.appendChild(urlText)

  const score = document.createElement('p')
  score.textContent = `Status: ${topScan.status} - Safety score ${topScan.score}/100`
  score.style.cssText = `margin:8px 0 0;color:${accentColor};font-weight:700`
  popup.appendChild(score)

  if (isSafe) {
    const safeText = document.createElement('p')
    safeText.textContent = 'No strong phishing indicators were found for this result.'
    safeText.style.cssText = 'margin:10px 0 0;color:#cbd5e1'
    popup.appendChild(safeText)
  }

  if (warningSigns.length > 0) {
    const list = document.createElement('ul')
    list.style.cssText = 'margin:10px 0 0;padding-left:18px;color:#f1f5f9'
    warningSigns.forEach((sign) => {
      const item = document.createElement('li')
      item.textContent = sign
      list.appendChild(item)
    })
    popup.appendChild(list)
  }

  if (recommendations.length > 0) {
    const recommendation = document.createElement('p')
    recommendation.textContent = recommendations[0]
    recommendation.style.cssText = 'margin:10px 0 0;color:#cbd5e1'
    popup.appendChild(recommendation)
  }

  const details = document.createElement('a')
  setDetailsHref(details, topUrl)
  details.target = '_blank'
  details.rel = 'noreferrer'
  details.textContent = 'Open in Tracking Threats'
  details.style.cssText = [
    'display:inline-flex',
    'margin-top:12px',
    'border-radius:8px',
    'background:#f8fafc',
    `color:${buttonColor}`,
    'font-weight:700',
    'padding:8px 10px',
    'text-decoration:none',
  ].join(';')
  popup.appendChild(details)

  if (!existing) document.body.appendChild(popup)
}

function createPreviewButton(text, variant = 'secondary') {
  const button = document.createElement('button')
  button.type = 'button'
  button.textContent = text
  const primary = variant === 'primary'
  const danger = variant === 'danger'
  button.style.cssText = [
    'all:initial',
    'box-sizing:border-box',
    'display:inline-flex',
    'align-items:center',
    'justify-content:center',
    'min-height:38px',
    'border-radius:8px',
    `border:1px solid ${primary ? 'rgba(20,184,166,.55)' : danger ? 'rgba(225,29,72,.55)' : 'rgba(148,163,184,.35)'}`,
    `background:${primary ? '#0f766e' : danger ? '#ffe4e6' : 'rgba(15,23,42,.8)'}`,
    `color:${primary ? '#fff' : danger ? '#9f1239' : '#e2e8f0'}`,
    'cursor:pointer',
    'font:700 13px/1 Arial,sans-serif',
    'padding:0 12px',
    'white-space:nowrap',
  ].join(';')
  return button
}

function showClickPreview(url, scan, anchor) {
  document.getElementById('threattrack-click-preview')?.remove()

  const style = getResultStyle(scan)
  const level = getScanLevel(scan)
  const accentColor =
    level === 'dangerous'
      ? '#fecdd3'
      : level === 'caution'
        ? '#fde68a'
        : '#6ee7b7'
  const warnings = scan.warningSigns?.slice(0, 4) ?? []
  const recommendations = scan.recommendations?.slice(0, 2) ?? []
  const overlay = document.createElement('div')
  overlay.id = 'threattrack-click-preview'
  overlay.style.cssText = [
    'position:fixed',
    'inset:0',
    'z-index:2147483647',
    'box-sizing:border-box',
    'display:flex',
    'align-items:center',
    'justify-content:center',
    'background:rgba(2,6,23,.58)',
    'padding:20px',
  ].join(';')

  const card = document.createElement('section')
  card.style.cssText = [
    'box-sizing:border-box',
    'width:min(560px,calc(100vw - 32px))',
    `border:1px solid ${style.border}`,
    'border-radius:10px',
    'background:#111827',
    'color:#f8fafc',
    'box-shadow:0 24px 80px rgba(0,0,0,.52)',
    'font:14px/1.45 Arial,sans-serif',
    'padding:18px',
  ].join(';')

  const heading = document.createElement('div')
  heading.style.cssText = 'display:flex;align-items:start;justify-content:space-between;gap:12px'

  const title = document.createElement('div')
  title.innerHTML = `<strong style="display:block;font-size:16px;color:${accentColor}">Tracking Threats Link Preview</strong><span style="color:#cbd5e1">Review this result before opening it.</span>`

  const close = createPreviewButton('x')
  close.style.width = '34px'
  close.style.minHeight = '34px'
  close.style.padding = '0'
  close.addEventListener('click', () => overlay.remove())

  heading.append(title, close)
  card.appendChild(heading)

  const urlText = document.createElement('p')
  urlText.textContent = url
  urlText.style.cssText = 'margin:14px 0 0;overflow-wrap:anywhere;color:#e2e8f0'
  card.appendChild(urlText)

  const score = document.createElement('p')
  score.textContent = `Status: ${scan.status} - Safety score ${scan.score}/100`
  score.style.cssText = `margin:10px 0 0;color:${accentColor};font-weight:700`
  card.appendChild(score)

  if (warnings.length > 0) {
    const list = document.createElement('ul')
    list.style.cssText = 'margin:12px 0 0;padding-left:18px;color:#f1f5f9'
    warnings.forEach((warning) => {
      const item = document.createElement('li')
      item.textContent = warning
      list.appendChild(item)
    })
    card.appendChild(list)
  }

  if (recommendations.length > 0) {
    const recommendation = document.createElement('p')
    recommendation.textContent = recommendations[0]
    recommendation.style.cssText = 'margin:12px 0 0;color:#cbd5e1'
    card.appendChild(recommendation)
  }

  const actions = document.createElement('div')
  actions.style.cssText = 'display:flex;flex-wrap:wrap;gap:10px;margin-top:16px'

  const details = document.createElement('a')
  setDetailsHref(details, url)
  details.target = '_blank'
  details.rel = 'noreferrer'
  details.textContent = 'Open details'
  details.style.cssText = createPreviewButton('Open details', 'primary').style.cssText

  const cancel = createPreviewButton('Stay on results')
  cancel.addEventListener('click', () => overlay.remove())

  const continueButton = createPreviewButton('Continue anyway', 'danger')
  continueButton.addEventListener('click', () => {
    overlay.remove()
    if (anchor.target === '_blank') {
      window.open(url, '_blank', 'noopener,noreferrer')
      return
    }
    window.location.href = url
  })

  actions.append(details, cancel, continueButton)
  card.appendChild(actions)
  overlay.appendChild(card)
  document.body.appendChild(overlay)
}

function scanGoogleResults() {
  showSearchStatus()
  collectResultLinks().forEach((url) => {
    if (scannedResults.has(url)) return
    scannedResults.set(url, null)

    chrome.runtime.sendMessage({
      type: 'scan-candidate-url',
      url,
      reason: 'google-search-result',
    }, (response) => {
      scannedResults.set(url, response.scan)
      if (!response?.ok || !response.scan) return
      latestResults.set(url, response.scan)
      const level = getScanLevel(response.scan)
      scanStats.checked += 1
      scanStats[level] += 1
      if (isRiskyScan(response.scan)) riskyResults.set(url, response.scan)
      markSearchLinks(url, response.scan)
      showSearchStatus()
      showResultPopup(url, response.scan)
    })
  })
}

function scheduleScan() {
  window.clearTimeout(scanTimer)
  scanTimer = window.setTimeout(scanGoogleResults, 500)
}

document.addEventListener(
  'click',
  (event) => {
    const anchor = event.target.closest?.('a[href]')
    if (!anchor) return

    const normalized = normalizeCandidate(anchor.getAttribute('href'))
    const scan = scannedResults.get(normalized)
    if (!scan || !isRiskyScan(scan)) return

    event.preventDefault()
    event.stopPropagation()
    showClickPreview(normalized, scan, anchor)
  },
  true,
)

scanGoogleResults()

const observer = new MutationObserver(scheduleScan)
observer.observe(document.body, { childList: true, subtree: true })
