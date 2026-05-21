const MAX_RESULTS_TO_SCAN = 12
const GOOGLE_REDIRECT_PATHS = new Set(['/url', '/interstitial'])
const SEARCH_ENGINE_HOSTS = [
  'google.com',
  'bing.com',
  'duckduckgo.com',
  'yahoo.com',
]
const APP_URL = 'http://localhost:5173/'
const scannedResults = new Map()
const riskyResults = new Map()
let scanTimer = null

function isSearchEngineHost(hostname) {
  return SEARCH_ENGINE_HOSTS.some((host) => hostname === host || hostname.endsWith(`.${host}`))
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
  const candidates = new Set()

  document.querySelectorAll('a[href]').forEach((anchor) => {
    const href = anchor.getAttribute('href')
    const normalized = href ? normalizeCandidate(href) : null
    if (normalized) candidates.add(normalized)
  })

  return Array.from(candidates).slice(0, MAX_RESULTS_TO_SCAN)
}

function isRiskyScan(scan) {
  return scan?.status === 'Dangerous' || scan?.status === 'Suspicious' || scan?.blocked
}

function getDetailsUrl(url) {
  const detailsUrl = new URL(APP_URL)
  detailsUrl.searchParams.set('page', 'history')
  detailsUrl.searchParams.set('blocked', url)
  return detailsUrl.toString()
}

function getWarningText(scan, url) {
  const warningSigns = scan.warningSigns?.length
    ? `\n\nWarning signs:\n- ${scan.warningSigns.slice(0, 4).join('\n- ')}`
    : ''
  const recommendations = scan.recommendations?.length
    ? `\n\nRecommendations:\n- ${scan.recommendations.slice(0, 3).join('\n- ')}`
    : ''

  return `Tracking Threats warning\n\n${url}\n\nStatus: ${scan.status} - Safety score ${
    scan.score
  }/100${warningSigns}${recommendations}\n\nContinue to this link?`
}

function addBadge(anchor, scan) {
  if (anchor.dataset.threattrackMarked === 'true') return false

  anchor.dataset.threattrackMarked = 'true'
  anchor.dataset.threattrackStatus = scan.status

  const badge = document.createElement('span')
  badge.className = 'threattrack-result-badge'
  badge.textContent = scan.status === 'Dangerous' ? 'Danger risk' : 'Caution'
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
    'border:1px solid rgba(225,29,72,.35)',
    'border-radius:999px',
    'background:#ffe4e6',
    'color:#9f1239',
    'font:700 11px/20px Arial,sans-serif',
    'padding:0 8px',
    'white-space:nowrap',
    'text-decoration:none',
    'vertical-align:middle',
  ].join(';')

  const title = anchor.querySelector('h3')
  if (title) {
    title.appendChild(badge)
  } else {
    anchor.insertAdjacentElement('afterend', badge)
  }

  return true
}

function markGoogleLinks(url, scan) {
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
    titleAnchors.forEach((anchor) => addBadge(anchor, scan))
    return
  }

  if (textAnchors.length > 0) {
    textAnchors.forEach((anchor) => addBadge(anchor, scan))
  }
}

function showRiskPopup() {
  const existing = document.getElementById('threattrack-google-warning')
  const results = Array.from(riskyResults.entries())
  if (results.length === 0) return

  const [topUrl, topScan] = results[0]
  const warningSigns = topScan.warningSigns?.slice(0, 3) ?? []
  const recommendations = topScan.recommendations?.slice(0, 2) ?? []
  const popup = existing ?? document.createElement('aside')

  popup.id = 'threattrack-google-warning'
  popup.style.cssText = [
    'position:fixed',
    'right:20px',
    'top:92px',
    'z-index:2147483647',
    'box-sizing:border-box',
    'width:min(360px,calc(100vw - 32px))',
    'border:1px solid rgba(225,29,72,.45)',
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
  title.innerHTML = `<strong style="display:block;font-size:14px;color:#fecdd3">Tracking Threats Warning</strong><span style="color:#cbd5e1">${results.length} risky Google result${results.length === 1 ? '' : 's'} detected before opening.</span>`

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
  score.style.cssText = 'margin:8px 0 0;color:#fecdd3;font-weight:700'
  popup.appendChild(score)

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
  details.href = getDetailsUrl(topUrl)
  details.target = '_blank'
  details.rel = 'noreferrer'
  details.textContent = 'See why this was flagged'
  details.style.cssText = [
    'display:inline-flex',
    'margin-top:12px',
    'border-radius:8px',
    'background:#f8fafc',
    'color:#9f1239',
    'font-weight:700',
    'padding:8px 10px',
    'text-decoration:none',
  ].join(';')
  popup.appendChild(details)

  if (!existing) document.body.appendChild(popup)
}

function scanGoogleResults() {
  collectResultLinks().forEach((url) => {
    if (scannedResults.has(url)) return
    scannedResults.set(url, null)

    chrome.runtime.sendMessage({
      type: 'scan-candidate-url',
      url,
      reason: 'google-search-result',
    }, (response) => {
      if (!response?.ok || !isRiskyScan(response.scan)) return
      scannedResults.set(url, response.scan)
      riskyResults.set(url, response.scan)
      markGoogleLinks(url, response.scan)
      showRiskPopup()
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

    const shouldContinue = window.confirm(getWarningText(scan, normalized))
    if (!shouldContinue) {
      event.preventDefault()
      event.stopPropagation()
    }
  },
  true,
)

scanGoogleResults()

const observer = new MutationObserver(scheduleScan)
observer.observe(document.body, { childList: true, subtree: true })
