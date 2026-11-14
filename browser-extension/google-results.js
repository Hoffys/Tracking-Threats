function hasIncompleteChecks(scan) {
  const coverage = scan?.coverage
  return coverage?.status !== 'complete' || coverage.checkedProviders < coverage.totalProviders ||
    coverage.linksChecked < coverage.totalLinks
}

function getCoverageText(scan) {
  const coverage = scan?.coverage
  if (!coverage) return 'Scan finished. Check details were not recorded; no further checks are pending.'
  const labels = { complete: 'All configured reputation checks responded', partial: 'Some reputation checks were unavailable or skipped', unavailable: 'Reputation checks were unavailable', 'local-only': 'Local analysis only' }
  const links = Number.isInteger(coverage.totalLinks) ? `; ${coverage.linksChecked}/${coverage.totalLinks} links checked` : ''
  return `Scan finished. ${labels[coverage.status] ?? 'Check details unavailable'}. No further checks are pending. ${coverage.checkedProviders}/${coverage.totalProviders} providers checked${links}. ${(coverage.limitations ?? []).join(' ')}`
}

function getCategoryText(scan) {
  const labels = { 'phishing-indicators': 'Phishing indicators', 'malware-reputation': 'Malware reputation', 'ip-reputation': 'IP reputation', 'file-risk': 'File risk', 'gambling-content': 'Gambling content', 'piracy-content': 'Piracy content' }
  const categories = (scan?.categories ?? []).filter((category) => Object.hasOwn(labels, category))
  const content = categories.filter((category) => category.endsWith('-content'))
  const risk = categories.filter((category) => !category.endsWith('-content'))
  const piracyCaution = categories.includes('piracy-content') ? 'Download risk is unknown. Piracy-related sources may expose you to malware, fake mirrors, tampered files, and copyright risk.' : ''
  return [(scan?.categoryWarnings?.length ? 'Content category warnings (not phishing proof): ' + scan.categoryWarnings.join(' ') : ''), risk.length ? 'Risk categories: ' + risk.map((category) => labels[category]).join(', ') + '.' : '', content.length ? 'Content warnings: ' + content.map((category) => labels[category]).join(', ') + '. These do not establish phishing.' : '', piracyCaution].filter(Boolean).join(' ')
}

function appendThreatClassification(parent, scan, includeReason = true) {
  if (scan?.threatName && scan?.threatType) {
    const classification = document.createElement('div')
    classification.style.cssText = 'margin:10px 0 0;border:1px solid rgba(148,163,184,.35);border-radius:8px;padding:10px;color:#e2e8f0'
    const heading = document.createElement('strong')
    heading.textContent = `Threat name: ${scan.threatName}`
    heading.style.cssText = 'display:block;color:#f8fafc'
    const type = document.createElement('p')
    type.textContent = `Threat type: ${scan.threatType}${scan.confidence ? ` - Confidence: ${scan.confidence}` : ''}`
    type.style.cssText = 'margin:4px 0 0'
    classification.append(heading, type)
    if (includeReason) {
      const reason = document.createElement('p')
      reason.textContent = `Why: ${scan.whyDetected?.[0] || scan.warningSigns?.[0] || scan.summary || 'Review the scan evidence.'}`
      reason.style.cssText = 'margin:4px 0 0;color:#cbd5e1'
      classification.appendChild(reason)
    }
    parent.appendChild(classification)
  }
}

function appendScanExplanation(parent, scan, includeReason = true) {
  if (includeReason && scan?.threatName && scan?.threatType) {
    const reason = document.createElement('div')
    reason.textContent = `Why: ${scan.whyDetected?.[0] || scan.warningSigns?.[0] || scan.summary || 'Review the scan evidence.'}`
    reason.style.cssText = 'margin:10px 0 0;border:1px solid rgba(148,163,184,.35);border-radius:8px;padding:10px;color:#cbd5e1'
    parent.appendChild(reason)
  }
  const detail = document.createElement('p')
  detail.textContent = [getCoverageText(scan), getCategoryText(scan), 'Rule-based score; not a calibrated probability.'].filter(Boolean).join(' ')
  detail.style.cssText = `margin:10px 0 0;color:${hasIncompleteChecks(scan) ? '#fde68a' : '#cbd5e1'}`
  parent.appendChild(detail)
}

function appendScanDetailsDisclosure(parent, scan, includeClassification = true, includeReason = true) {
  const details = document.createElement('details')
  details.style.cssText = 'margin-top:10px;border-top:1px solid #263449;padding-top:8px'
  const summary = document.createElement('summary')
  summary.textContent = 'View more details'
  summary.style.cssText = 'color:#99f6e4;cursor:pointer;font:700 12px/1.4 Arial,sans-serif'
  details.appendChild(summary)
  if (includeClassification) appendThreatClassification(details, scan)
  appendScanExplanation(details, scan, includeReason && !includeClassification)
  parent.appendChild(details)
}

const MAX_RESULTS_TO_SCAN = 50
const MAX_RESULTS_PER_PAGE = MAX_RESULTS_TO_SCAN
const SEARCH_MONITOR_CONSENT_VERSION = '2026.10'
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
const ADVERTISEMENT_SELECTORS = [
  '#tads', '#tadsb', '[data-text-ad]', '[data-ad-slot]', '[data-testid*="advert"]', '[data-testid*="sponsor"]',
  '.uEierd', '.b_ad', '.result--ad',
  '[aria-label*="Sponsored" i]', '[aria-label*="Advertisement" i]',
].join(',')
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
  incomplete: 0,
  failed: 0,
  caution: 0,
  dangerous: 0,
  content: 0,
}
let scanTimer = null
let searchConsentDecision = 'checking'
let searchConsentGeneration = 0

function isSearchEngineHost(hostname) {
  return SEARCH_ENGINE_HOSTS.some((host) => hostname === host || hostname.endsWith(`.${host}`))
}

function isVisible(element) {
  const rect = element.getBoundingClientRect()
  return rect.width > 0 && rect.height > 0
}

function isAdvertisement(anchor) {
  return Boolean(anchor.closest(ADVERTISEMENT_SELECTORS))
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
    if (!anchor || !isVisible(anchor) || isAdvertisement(anchor)) return
    const href = anchor.getAttribute('href')
    const normalized = href ? normalizeCandidate(href) : null
    if (!normalized || seen.has(normalized)) return
    seen.add(normalized)
    candidates.push(normalized)
  })

  return candidates.slice(0, MAX_RESULTS_TO_SCAN)
}

function isRiskyScan(scan) {
  return hasPiracyContent(scan) || scan?.status === 'Dangerous' || scan?.status === 'Suspicious' || scan?.blocked
}

function hasPiracyContent(scan) {
  return scan?.categories?.includes('piracy-content') === true
}

function hasContentWarnings(scan) {
  return scan?.categories?.some((category) => typeof category === 'string' && category.endsWith('-content')) === true
}

function getScoreText(scan) {
  if (hasPiracyContent(scan)) {
    return `URL phishing safety score: ${scan.score}/100. Downloaded files were not scanned.`
  }
  if (scan?.status === 'Safe' && hasContentWarnings(scan)) {
    return `Phishing safety score: ${scan.score}/100. A separate content warning applies.`
  }
  return `Rule-based safety score: ${scan.score}/100`
}

function getScanLevel(scan) {
  if (scan?.status === 'Dangerous' || scan?.blocked) return 'dangerous'
  if (scan?.status === 'Suspicious') return 'caution'
  if (scan?.status === 'Safe' && hasContentWarnings(scan)) return 'content'
  if (hasIncompleteChecks(scan)) return 'incomplete'
  return 'safe'
}

function getResultStyle(scan) {
  const level = getScanLevel(scan)
  if (level === 'dangerous') {
    return {
      label: 'RISK DETECTED',
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
  if (level === 'content') {
    return {
      label: hasPiracyContent(scan) ? 'CAUTION - PIRACY RISK' : 'CONTENT WARNING',
      border: 'rgba(245,158,11,.55)',
      background: '#fef3c7',
      color: '#92400e',
      rowBackground: 'rgba(245,158,11,.12)',
    }
  }
  return {
    label: 'APPEARS SAFE',
    border: 'rgba(16,185,129,.45)',
    background: '#ccfbf1',
    color: '#115e59',
    rowBackground: 'rgba(16,185,129,.08)',
  }
}

function getDetailsUrl(url, appUrl = APP_URL, scan = null) {
  const detailsUrl = new URL(APP_URL)
  detailsUrl.href = appUrl
  detailsUrl.searchParams.set('page', 'history')
  detailsUrl.searchParams.delete('scan')
  detailsUrl.searchParams.delete('blocked')
  detailsUrl.searchParams.delete('preview')
  detailsUrl.hash = ''
  if (scan) {
    detailsUrl.searchParams.set('preview', '1')
    // Carry the displayed result without saving it or running another scan.
    // A fragment stays in the browser rather than entering server request logs.
    detailsUrl.hash = new URLSearchParams({ preview: JSON.stringify({
      target: url,
      status: scan.status,
      score: scan.score,
      summary: scan.summary,
      warningSigns: scan.warningSigns ?? [],
      recommendations: scan.recommendations ?? [],
      coverage: scan.coverage,
      categories: scan.categories,
      categoryWarnings: scan.categoryWarnings,
      threatName: scan.threatName,
      threatType: scan.threatType,
      confidence: scan.confidence,
      whyDetected: scan.whyDetected,
      evidenceSources: scan.evidenceSources,
    }) }).toString()
  } else {
    detailsUrl.searchParams.set('blocked', url)
  }
  return detailsUrl.toString()
}

function isExtensionContextInvalidated(error) {
  return /extension context invalidated/i.test(String(error?.message ?? error ?? ''))
}

function sendRuntimeMessage(message, callback) {
  const contextUnavailable = { ok: false, error: 'Extension context invalidated' }
  const invoke = (response, lastError = null) => {
    try {
      callback(response, lastError)
    } catch (error) {
      if (isExtensionContextInvalidated(error)) return
      throw error
    }
  }

  try {
    if (typeof chrome === 'undefined' || !chrome.runtime?.sendMessage) {
      invoke(contextUnavailable, contextUnavailable)
      return
    }
    chrome.runtime.sendMessage(message, (response) => {
      let lastError = null
      try {
        lastError = chrome.runtime.lastError ?? null
      } catch (error) {
        if (!isExtensionContextInvalidated(error)) throw error
        invoke(contextUnavailable, error)
        return
      }
      invoke(response, lastError)
    })
  } catch (error) {
    if (!isExtensionContextInvalidated(error)) throw error
    invoke(contextUnavailable, error)
  }
}

function setDetailsHref(anchor, url, scan) {
  anchor.href = getDetailsUrl(url, APP_URL, scan)
  sendRuntimeMessage({ type: 'get-linked-app-url' }, (response, lastError) => {
    if (lastError || !response?.ok || !response.appUrl) return
    anchor.href = getDetailsUrl(url, response.appUrl, scan)
  })
}

function showSafetyScoreModal(url, scan, returnFocus = null) {
  document.getElementById('threattrack-safety-score-modal')?.remove()

  const status = scan?.status ?? scan?.risk ?? 'Unknown'
  const dangerous = status === 'Dangerous'
  const suspicious = status === 'Suspicious'
  const safe = status === 'Safe'
  const palette = dangerous
    ? { accent: '#fda4af', border: 'rgba(251,113,133,.42)', panel: 'rgba(127,29,29,.25)', soft: '#4c0519', label: 'High Risk' }
    : suspicious
      ? { accent: '#fcd34d', border: 'rgba(251,191,36,.42)', panel: 'rgba(120,53,15,.24)', soft: '#451a03', label: 'Caution' }
      : safe
        ? { accent: '#6ee7b7', border: 'rgba(52,211,153,.4)', panel: 'rgba(6,78,59,.25)', soft: '#022c22', label: 'Low Risk' }
        : { accent: '#cbd5e1', border: 'rgba(148,163,184,.38)', panel: 'rgba(51,65,85,.45)', soft: '#1e293b', label: 'Unverified' }
  const score = typeof scan?.score === 'number' && Number.isFinite(scan.score) && scan.score >= 0 && scan.score <= 100
    ? scan.score
    : null
  const overlay = document.createElement('div')
  overlay.id = 'threattrack-safety-score-modal'
  overlay.setAttribute('role', 'presentation')
  overlay.style.cssText = 'position:fixed;inset:0;z-index:2147483647;box-sizing:border-box;display:flex;align-items:center;justify-content:center;background:rgba(2,6,23,.72);padding:clamp(10px,3vw,24px)'

  const dialog = document.createElement('section')
  dialog.setAttribute('role', 'dialog')
  dialog.setAttribute('aria-modal', 'true')
  dialog.setAttribute('aria-labelledby', 'threattrack-score-title')
  dialog.setAttribute('aria-describedby', 'threattrack-score-summary')
  dialog.tabIndex = -1
  dialog.style.cssText = `box-sizing:border-box;display:flex;flex-direction:column;width:min(900px,100%);max-height:calc(100vh - 20px);max-height:calc(100dvh - 20px);overflow:hidden;border:1px solid ${palette.border};border-radius:18px;background:#0b1220;color:#f8fafc;box-shadow:0 28px 90px rgba(0,0,0,.58);font:14px/1.5 Arial,sans-serif`

  const addText = (parent, text, css = '', tagName = 'p') => {
    const node = document.createElement(tagName)
    node.textContent = text
    node.style.cssText = css
    parent.appendChild(node)
    return node
  }
  const makeCard = (parent, titleText, subtitle = '') => {
    const section = document.createElement('section')
    section.style.cssText = 'min-width:0;border:1px solid #263449;border-radius:14px;background:rgba(15,23,42,.76);padding:16px'
    const heading = document.createElement('h3')
    heading.textContent = titleText
    heading.style.cssText = 'margin:0;color:#f8fafc;font-size:14px;font-weight:700;letter-spacing:.01em'
    section.appendChild(heading)
    if (subtitle) addText(section, subtitle, 'margin:4px 0 0;color:#94a3b8;font-size:12px;line-height:1.5')
    parent.appendChild(section)
    return section
  }
  const addPill = (parent, text, color = palette.accent, background = palette.soft) => {
    const pill = document.createElement('span')
    pill.textContent = text
    pill.style.cssText = `display:inline-flex;align-items:center;max-width:100%;border:1px solid ${palette.border};border-radius:999px;background:${background};color:${color};padding:3px 9px;font:700 11px/1.4 Arial,sans-serif;white-space:normal`
    parent.appendChild(pill)
    return pill
  }
  const resultStatusStyles = {
    Clean: { color: '#6ee7b7', background: 'rgba(6,78,59,.28)', border: 'rgba(52,211,153,.35)' },
    'No Issues': { color: '#6ee7b7', background: 'rgba(6,78,59,.28)', border: 'rgba(52,211,153,.35)' },
    'No Threats': { color: '#6ee7b7', background: 'rgba(6,78,59,.28)', border: 'rgba(52,211,153,.35)' },
    'Potential Risk': { color: '#fcd34d', background: 'rgba(120,53,15,.3)', border: 'rgba(251,191,36,.4)' },
    Informational: { color: '#cbd5e1', background: 'rgba(51,65,85,.45)', border: 'rgba(148,163,184,.35)' },
    Malicious: { color: '#fda4af', background: 'rgba(127,29,29,.3)', border: 'rgba(251,113,133,.4)' },
    'Threat Detected': { color: '#fda4af', background: 'rgba(127,29,29,.3)', border: 'rgba(251,113,133,.4)' },
    Unavailable: { color: '#fcd34d', background: 'rgba(120,53,15,.24)', border: 'rgba(251,191,36,.35)' },
    'Check Incomplete': { color: '#fcd34d', background: 'rgba(120,53,15,.24)', border: 'rgba(251,191,36,.35)' },
    'Not run': { color: '#cbd5e1', background: 'rgba(51,65,85,.45)', border: 'rgba(148,163,184,.35)' },
    'Details unavailable': { color: '#cbd5e1', background: 'rgba(51,65,85,.45)', border: 'rgba(148,163,184,.35)' },
    'Partial Results': { color: '#fcd34d', background: 'rgba(120,53,15,.24)', border: 'rgba(251,191,36,.35)' },
    'No Results Listed': { color: '#cbd5e1', background: 'rgba(51,65,85,.45)', border: 'rgba(148,163,184,.35)' },
  }
  const addResultStatus = (parent, label) => {
    const style = resultStatusStyles[label] ?? resultStatusStyles['Details unavailable']
    const badge = document.createElement('span')
    badge.textContent = label
    badge.style.cssText = `display:inline-flex;align-items:center;border:1px solid ${style.border};border-radius:999px;background:${style.background};color:${style.color};padding:4px 9px;font:700 11px/1.35 Arial,sans-serif`
    parent.appendChild(badge)
    return badge
  }
  const makeFindingCard = (parent, titleText, subtitle, icon, statusLabel) => {
    const section = document.createElement('section')
    section.style.cssText = 'min-width:0;border:1px solid #263449;border-radius:14px;background:rgba(15,23,42,.76);padding:15px'
    const headerRow = document.createElement('div')
    headerRow.style.cssText = 'display:flex;align-items:center;gap:10px;min-width:0'
    const iconBox = document.createElement('span')
    iconBox.textContent = icon
    iconBox.setAttribute('aria-hidden', 'true')
    iconBox.style.cssText = `display:grid;place-items:center;flex:0 0 34px;width:34px;height:34px;border:1px solid ${palette.border};border-radius:10px;background:${palette.panel};color:${palette.accent};font:700 16px Arial,sans-serif`
    const title = document.createElement('h3')
    title.textContent = titleText
    title.style.cssText = 'flex:1 1 auto;min-width:0;margin:0;color:#f8fafc;font-size:14px;font-weight:700;letter-spacing:.01em'
    headerRow.append(iconBox, title)
    section.appendChild(headerRow)
    addResultStatus(section, statusLabel)
    addText(section, subtitle, 'margin:8px 0 0;color:#94a3b8;font-size:12px;line-height:1.5')
    parent.appendChild(section)
    return section
  }
  const displayStatus = ['Safe', 'Suspicious', 'Dangerous'].includes(status) ? status : 'Unverified'
  const scoreDescriptions = {
    Safe: 'Fewer risk indicators were detected in the checks that ran. Proceed with normal caution.',
    Suspicious: 'Warning signs were detected. Verify this website through a trusted source before continuing.',
    Dangerous: 'Threat indicators were detected. Avoid visiting this website and do not enter personal information.',
  }
  const scoreDescription = scoreDescriptions[status] ?? 'The scan did not return a recognized security classification.'

  const header = document.createElement('div')
  header.style.cssText = 'flex:0 0 auto;display:flex;align-items:center;justify-content:space-between;gap:14px;border-bottom:1px solid #263449;padding:16px clamp(16px,3vw,24px)'
  const brandBlock = document.createElement('div')
  brandBlock.style.cssText = 'display:flex;align-items:center;gap:12px;min-width:0'
  const brandIcon = document.createElement('img')
  brandIcon.src = chrome.runtime.getURL('icons/icon-32.png')
  brandIcon.alt = ''
  brandIcon.setAttribute('aria-hidden', 'true')
  brandIcon.style.cssText = 'display:block;flex:0 0 auto;width:46px;height:46px;border-radius:12px;object-fit:contain'
  const brandText = document.createElement('div')
  brandText.style.cssText = 'min-width:0'
  addText(brandText, 'TRACKING THREATS', 'margin:0;color:#5eead4;font-size:10px;font-weight:800;letter-spacing:.16em', 'p')
  const title = document.createElement('h2')
  title.id = 'threattrack-score-title'
  title.textContent = 'Safety Score Details'
  title.style.cssText = 'margin:2px 0 0;color:#f8fafc;font-size:17px;font-weight:700;line-height:1.3'
  brandText.appendChild(title)
  brandBlock.append(brandIcon, brandText)
  const close = document.createElement('button')
  close.type = 'button'
  close.textContent = '×'
  close.setAttribute('aria-label', 'Close safety score details')
  close.style.cssText = 'display:grid;place-items:center;flex:0 0 auto;width:38px;height:38px;border:1px solid #334155;border-radius:10px;background:#111827;color:#cbd5e1;font:400 24px/1 Arial,sans-serif;cursor:pointer'
  const dismiss = () => { overlay.remove(); returnFocus?.focus?.() }
  close.addEventListener('click', dismiss)
  header.append(brandBlock, close)
  dialog.appendChild(header)

  const content = document.createElement('div')
  content.style.cssText = 'flex:1 1 auto;min-height:0;overflow:auto;overscroll-behavior:contain;-webkit-overflow-scrolling:touch;padding:clamp(14px,3vw,24px)'
  dialog.appendChild(content)

  const scorePanel = document.createElement('section')
  scorePanel.style.cssText = `border:1px solid ${palette.border};border-radius:16px;background:${palette.panel};padding:clamp(16px,3vw,24px)`
  const scoreTop = document.createElement('div')
  scoreTop.style.cssText = 'display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px'
  const scoreCopy = document.createElement('div')
  scoreCopy.style.cssText = 'flex:1 1 300px;min-width:0'
  const scoreLabel = document.createElement('p')
  scoreLabel.textContent = 'URL SAFETY SCORE'
  scoreLabel.style.cssText = 'margin:0;color:#94a3b8;font-size:10px;font-weight:800;letter-spacing:.15em'
  scoreCopy.appendChild(scoreLabel)
  addPill(scoreCopy, `${displayStatus} · ${palette.label}`)
  if (dangerous) addText(scoreCopy, 'Why is this website dangerous?', 'margin:10px 0 0;color:#fda4af;font-size:15px;font-weight:700', 'h3')
  addText(scoreCopy, scoreDescription, 'margin:10px 0 0;color:#e2e8f0;font-size:14px;line-height:1.6', 'p').id = 'threattrack-score-summary'
  const scoreIndicator = document.createElement('div')
  scoreIndicator.setAttribute('role', 'progressbar')
  scoreIndicator.setAttribute('aria-label', 'Safety score')
  scoreIndicator.setAttribute('aria-valuemin', '0')
  scoreIndicator.setAttribute('aria-valuemax', '100')
  if (score !== null) {
    scoreIndicator.setAttribute('aria-valuenow', String(score))
    scoreIndicator.setAttribute('aria-valuetext', `${score} out of 100`)
  } else {
    scoreIndicator.setAttribute('aria-valuetext', 'Score unavailable')
  }
  scoreIndicator.style.cssText = `display:grid;place-items:center;flex:0 0 auto;width:clamp(94px,22vw,116px);aspect-ratio:1;border-radius:50%;background:conic-gradient(from -90deg,${palette.accent} ${score ?? 0}%,#334155 0)`
  const scoreCenter = document.createElement('div')
  scoreCenter.style.cssText = 'display:flex;flex-direction:column;align-items:center;justify-content:center;width:calc(100% - 12px);height:calc(100% - 12px);border-radius:50%;background:#101a2b;text-align:center'
  const scoreNumber = document.createElement('p')
  scoreNumber.textContent = score === null ? 'Unavailable' : String(score)
  scoreNumber.style.cssText = `max-width:100%;margin:0;color:${palette.accent};font-size:clamp(24px,6vw,32px);font-weight:800;line-height:1.05;letter-spacing:-.04em;overflow-wrap:anywhere`
  scoreCenter.appendChild(scoreNumber)
  if (score !== null) addText(scoreCenter, 'out of 100', 'margin:3px 0 0;color:#cbd5e1;font-size:10px')
  scoreIndicator.appendChild(scoreCenter)
  scoreTop.append(scoreCopy, scoreIndicator)
  scorePanel.appendChild(scoreTop)
  content.appendChild(scorePanel)

  const targetSection = makeCard(content, 'Target URL')
  targetSection.style.marginTop = '12px'
  addText(targetSection, url, 'margin:8px 0 0;color:#e2e8f0;overflow-wrap:anywhere;font-size:12px')

  const guide = makeCard(content, 'Safety Score Guide', 'These ranges match the URL scanner’s existing classification thresholds.')
  guide.style.marginTop = '16px'
  const guideGrid = document.createElement('div')
  guideGrid.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,190px),1fr));gap:10px;margin-top:12px'
  const guideItems = [
    { status: 'Safe', range: '80–100', text: 'Fewer indicators were detected. Proceed with normal caution.', color: '#6ee7b7', border: 'rgba(52,211,153,.35)', background: 'rgba(6,78,59,.18)' },
    { status: 'Suspicious', range: '51–79', text: 'Warning signs were detected. Verify the site before continuing.', color: '#fcd34d', border: 'rgba(251,191,36,.35)', background: 'rgba(120,53,15,.18)' },
    { status: 'Dangerous', range: '0–50', text: 'Threat indicators were detected. Avoid visiting the site.', color: '#fda4af', border: 'rgba(251,113,133,.35)', background: 'rgba(127,29,29,.18)' },
  ]
  guideItems.forEach((item) => {
    const guideItem = document.createElement('div')
    const current = status === item.status
    guideItem.setAttribute('aria-label', `${item.status}, ${item.range}${current ? ', current classification' : ''}`)
    guideItem.style.cssText = `min-width:0;border:1px solid ${current ? item.border : '#263449'};border-radius:12px;background:${current ? item.background : 'rgba(15,23,42,.42)'};padding:12px`
    const titleLine = document.createElement('div')
    titleLine.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:8px'
    addText(titleLine, item.status, `margin:0;color:${item.color};font-size:13px;font-weight:700`)
    addText(titleLine, item.range, 'margin:0;color:#cbd5e1;font-size:12px;font-variant-numeric:tabular-nums')
    guideItem.appendChild(titleLine)
    addText(guideItem, item.text, 'margin:7px 0 0;color:#cbd5e1;font-size:12px;line-height:1.5')
    guideGrid.appendChild(guideItem)
  })
  guide.appendChild(guideGrid)

  const found = makeCard(content, 'What We Found', 'Security checks and content-category warnings are reported separately.')
  found.style.marginTop = '16px'
  const findingGrid = document.createElement('div')
  findingGrid.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,230px),1fr));gap:12px;margin-top:12px'
  found.appendChild(findingGrid)

  const details = scan?.details && typeof scan.details === 'object' ? scan.details : null
  const categories = [...new Set([
    ...(Array.isArray(scan?.categories) ? scan.categories : []),
    ...(Array.isArray(details?.categories) ? details.categories : []),
  ])]
  const categoryWarnings = [...new Set([
    ...(Array.isArray(scan?.categoryWarnings) ? scan.categoryWarnings : []),
    ...(Array.isArray(details?.categoryWarnings) ? details.categoryWarnings : []),
  ].map((item) => typeof item === 'string' ? item : item?.label).filter(Boolean))]
  const contentCategories = categories.filter((category) => typeof category === 'string' && category.endsWith('-content'))
  const piracyRisk = categories.includes('piracy-content') || categoryWarnings.some((warning) => /piracy/i.test(warning))
  const providers = Array.isArray(details?.threatIntel) &&
      (details.threatIntel.length > 0 || !Array.isArray(scan?.threatIntel))
    ? details.threatIntel
    : Array.isArray(scan?.threatIntel) ? scan.threatIntel : null
  const pageProvider = (providers ?? []).find((provider) => ['Page inspection', 'Rendered page inspection'].includes(provider?.provider))
  const localRules = Array.isArray(details?.findings) ? details.findings : []
  const pageFindings = [...new Set([
    ...(Array.isArray(details?.pageInspection?.findings) ? details.pageInspection.findings : []),
    ...(Array.isArray(pageProvider?.inspection?.findings) ? pageProvider.inspection.findings.map((finding) => finding?.label) : []),
  ].filter((finding) => typeof finding === 'string' && finding.trim()))]
  const pageInspectionCompleted = pageProvider
    ? pageProvider.checked === true && !pageProvider.error && !pageProvider.skipped && (typeof pageProvider.found === 'boolean' || Boolean(pageProvider.inspection && typeof pageProvider.inspection === 'object'))
    : Boolean(details?.pageInspection && typeof details.pageInspection === 'object')
  const pageInspectionUnavailable = Boolean(pageProvider) && !pageInspectionCompleted
  const coverageLimitations = [
    ...(Array.isArray(scan?.coverage?.limitations) ? scan.coverage.limitations : []),
    ...(Array.isArray(details?.coverage?.limitations) ? details.coverage.limitations : []),
  ]
  const pageInspectionNotRun = !pageProvider && !details?.pageInspection && coverageLimitations.some((item) => typeof item === 'string' && /page content.*(?:not inspected|not checked)|page inspection.*not run/i.test(item))
  const pageInspectionHasFindings = pageFindings.length > 0 || pageProvider?.found === true
  const pageInspectionStatus = pageInspectionUnavailable
    ? 'Unavailable'
    : pageInspectionCompleted
      ? pageInspectionHasFindings ? 'Findings reported' : 'No findings detected'
      : pageInspectionNotRun ? 'Not run' : 'Details unavailable'
  const appendFinding = (parent, { nameText, evidence, deduction, whyMatters, deductionLabel = 'Score deduction' }) => {
      const card = document.createElement('div')
      card.style.cssText = 'margin-top:10px;border:1px solid #263449;border-radius:10px;background:rgba(2,6,23,.3);padding:11px'
      const name = document.createElement('strong')
      name.textContent = nameText
      name.style.cssText = 'display:block;color:#f8fafc'
      card.appendChild(name)
      const evidenceEntries = evidence && typeof evidence === 'object' && !Array.isArray(evidence)
        ? Object.entries(evidence).filter(([, value]) => value !== undefined)
        : []
      const evidenceSummary = evidenceEntries.map(([key, value]) => `${key}=${JSON.stringify(value)}`).join('; ')
      if (evidenceSummary) addText(card, `Why it triggered: The scan matched this rule using the recorded values: ${evidenceSummary}.`, 'margin:7px 0 0;color:#cbd5e1;overflow-wrap:anywhere;font-size:12px')
      if (whyMatters) addText(card, `Why it matters: ${whyMatters}`, 'margin:7px 0 0;color:#cbd5e1;font-size:12px')
      if (evidenceEntries.length > 0) {
        addText(card, `Evidence: ${JSON.stringify(Object.fromEntries(evidenceEntries))}`, 'margin:7px 0 0;color:#94a3b8;overflow-wrap:anywhere;font:11px/1.5 ui-monospace,Consolas,monospace')
      } else {
        addText(card, 'The scanner did not provide additional evidence details.', 'margin:7px 0 0;color:#94a3b8;font-size:12px')
      }
      if (deduction !== undefined && deduction !== null && Number.isFinite(Number(deduction)) && Number(deduction) > 0) {
        addText(card, `${deductionLabel}: −${Number(deduction)} points`, 'margin:7px 0 0;color:#f8fafc;font-size:12px;font-weight:700')
      } else {
        addText(card, 'No score deduction recorded.', 'margin:7px 0 0;color:#94a3b8;font-size:12px')
      }
      parent.appendChild(card)
  }
  const getPageFindingEvidence = (finding) => {
    const inspection = details?.pageInspection ?? pageProvider?.inspection
    const normalizedFinding = finding.toLowerCase()
    const evidenceKeys = normalizedFinding.includes('submits to a different host')
      ? ['passwordFields', 'externalFormActions']
      : normalizedFinding.includes('credential-entry form')
        ? ['passwordFields', 'credentialLanguage']
        : normalizedFinding.includes('meta-refresh')
          ? ['externalMetaRefresh']
          : normalizedFinding.includes('hidden forms') || normalizedFinding.includes('hidden frames')
            ? ['hiddenFrames', 'credentialLanguage']
            : normalizedFinding.includes('obfuscated script') || normalizedFinding.includes('obfuscated scripts')
              ? ['obfuscatedScripts', 'credentialLanguage']
              : []
    return inspection
      ? Object.fromEntries(evidenceKeys.filter((key) => inspection[key] !== undefined).map((key) => [key, inspection[key]]))
      : null
  }

  const externalProviders = (providers ?? []).filter((provider) => !['Page inspection', 'Rendered page inspection'].includes(provider?.provider))
  const checkedExternalProviders = externalProviders.filter((provider) => provider?.checked === true && !provider?.error && !provider?.skipped)
  const externalThreats = checkedExternalProviders.filter((provider) => provider?.found === true)
  const completeExternalProviders = checkedExternalProviders.filter((provider) => typeof provider?.found === 'boolean')
  const incompleteExternalCount = externalProviders.length - completeExternalProviders.length
  const externalStatus = providers === null || externalProviders.length === 0
    ? 'Check Incomplete'
    : externalThreats.length > 0
      ? 'Threat Detected'
      : completeExternalProviders.length === 0
        ? 'Check Incomplete'
        : incompleteExternalCount > 0 ? 'Partial Results' : 'No Threats'
  const externalSummary = externalThreats.length > 0
    ? incompleteExternalCount > 0 ? 'A threat was reported; other checks were incomplete.' : 'A completed threat-intelligence check reported a threat.'
    : providers === null || externalProviders.length === 0 || checkedExternalProviders.length === 0
      ? 'Threat-intelligence checks were unavailable or not included in the scan response.'
      : incompleteExternalCount > 0
        ? 'Some checks were unavailable, so a clean result cannot be confirmed.'
        : 'No known threats from trusted sources.'
  const urlStatus = !Array.isArray(details?.findings)
    ? 'Check Incomplete'
    : localRules.some((finding) => Number(finding?.deduction) > 0) || localRules.some((finding) => finding?.deduction === undefined || finding?.deduction === null)
      ? 'Potential Risk'
      : localRules.length ? 'Informational' : 'Clean'
  const firstUrlFinding = localRules.find((finding) => finding?.label || finding?.code)
  const urlSummary = !Array.isArray(details?.findings)
    ? 'URL reputation details were not included in this scan.'
    : urlStatus === 'Clean'
      ? 'No known malicious activity.'
      : urlStatus === 'Informational'
        ? 'Informational signals were recorded, with no score deduction.'
        : firstUrlFinding ? `Detected: ${firstUrlFinding.label || firstUrlFinding.code}.` : 'URL risk indicators were detected.'
  const urlGroup = makeFindingCard(findingGrid, 'URL Reputation', urlSummary, '↗', urlStatus)

  const pageCardStatus = pageInspectionUnavailable && pageInspectionHasFindings
    ? 'Partial Results'
    : pageInspectionStatus === 'Findings reported' ? 'Potential Risk'
      : pageInspectionStatus === 'No findings detected' ? 'No Issues'
        : pageInspectionStatus === 'Unavailable' || pageInspectionStatus === 'Details unavailable' ? 'Check Incomplete'
          : pageInspectionStatus
  const firstPageFinding = pageFindings[0]
  const pageSummary = pageCardStatus === 'No Issues'
    ? 'No suspicious content found.'
    : pageCardStatus === 'Potential Risk'
      ? firstPageFinding ? `Detected: ${firstPageFinding}.` : 'Page inspection reported a potential risk.'
      : pageCardStatus === 'Partial Results'
        ? `A finding was returned (${firstPageFinding || 'details unavailable'}), but inspection was incomplete.`
        : pageCardStatus === 'Not run'
          ? 'Page inspection was not run for this scan.'
          : 'Page inspection could not be completed or its details were unavailable.'
  const pageGroup = makeFindingCard(findingGrid, 'Page Inspection', pageSummary, '▤', pageCardStatus)
  const intel = makeFindingCard(findingGrid, 'External Intelligence', externalSummary, '◎', externalStatus)

  if (contentCategories.length > 0 || categoryWarnings.length > 0) {
    const contentGroup = makeCard(content, 'Content Category Warnings', 'These content warnings are separate from the URL security classification.')
    contentGroup.style.marginTop = '12px'
    contentCategories.forEach((category) => addPill(contentGroup, category, '#fcd34d', '#451a03'))
    if (categoryWarnings.length) {
      categoryWarnings.forEach((warning) => addText(contentGroup, warning, 'margin:8px 0 0;color:#fde68a;overflow-wrap:anywhere;font-size:12px'))
    } else {
      addText(contentGroup, 'Content-category indicators were recorded, but no warning explanation was included.', 'margin:8px 0 0;color:#cbd5e1;font-size:12px')
    }
    if (piracyRisk) {
      addText(contentGroup, 'Piracy-related content risk is not a phishing or malware finding. Downloaded files were not assessed by this URL score.', 'margin:8px 0 0;color:#cbd5e1;font-size:12px')
    }
  }

  const whyFlagged = makeCard(content, 'Why This URL Was Flagged', 'Only returned security findings are listed here.')
  whyFlagged.style.marginTop = '12px'
  const whyReasons = [
    ...localRules.map((finding) => ({
      source: 'URL Reputation',
      name: finding?.label || finding?.code || 'Finding details unavailable',
      evidence: finding?.evidence,
      deduction: finding?.deduction,
      whyMatters: 'This signal is included in URL analysis; its recorded deduction is shown when available.',
    })),
    ...pageFindings.map((finding) => ({
      source: 'Page Inspection',
      name: finding,
      evidence: getPageFindingEvidence(finding),
      deduction: pageProvider?.inspection?.findings?.find((item) => item?.label === finding)?.deduction,
      deductionLabel: 'Recorded page-inspection deduction',
      whyMatters: 'This signal is included in page inspection; its recorded deduction is shown when available.',
    })),
    ...(pageProvider?.checked === true && pageInspectionHasFindings && pageProvider.deduction !== undefined && pageProvider.deduction !== null && Number.isFinite(Number(pageProvider.deduction))
      ? [{
          source: 'Page Inspection',
          name: 'Combined page-inspection result',
          deduction: pageProvider.deduction,
          deductionLabel: 'Recorded combined page-inspection deduction',
          whyMatters: 'This is the recorded total deduction for page inspection.',
        }]
      : []),
    ...externalThreats.map((provider) => {
      const included = provider?.riskAffecting !== false && provider?.checked === true && !provider?.error && !provider?.skipped && Boolean(provider?.warning)
      return {
        source: 'External Intelligence',
        name: 'Threat intelligence finding',
        deduction: provider?.deduction,
        deductionLabel: 'Recorded external-intelligence deduction',
        whyMatters: included
          ? 'This threat match was included in the external reputation component.'
          : 'This threat match was reported but was not included in the external reputation component.',
      }
    }),
  ].filter((reason) => reason.name)
  if (whyReasons.length > 0) {
    if (status === 'Safe') {
      addText(whyFlagged, 'The scan returned a Safe classification. These findings were included in the scan response:', 'margin:8px 0 0;color:#cbd5e1;font-size:12px')
    } else {
      addText(whyFlagged, 'The scan returned a ' + displayStatus + ' classification. These findings were included in the scan response:', 'margin:8px 0 0;color:#cbd5e1;font-size:12px')
    }
    whyReasons.forEach((reason) => {
      const row = document.createElement('div')
      row.style.cssText = 'margin-top:8px;border-left:2px solid #475569;padding-left:10px'
      addText(row, reason.source, 'margin:0;color:#94a3b8;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em')
      appendFinding(row, { ...reason, nameText: reason.name })
      whyFlagged.appendChild(row)
    })
  } else if (['Suspicious', 'Dangerous'].includes(status)) {
    addText(whyFlagged, 'The scan returned a ' + displayStatus + ' classification, but rule-level reasons were not included in the available scan details.', 'margin:8px 0 0;color:#cbd5e1;font-size:12px')
  } else if (status === 'Safe') {
    addText(whyFlagged, 'No additional security findings were included in the available scan details.', 'margin:8px 0 0;color:#cbd5e1;font-size:12px')
  } else {
    addText(whyFlagged, 'The scan did not include enough detail to explain this classification.', 'margin:8px 0 0;color:#cbd5e1;font-size:12px')
  }

  const calculation = makeCard(content, 'How the Score Is Calculated', 'The score reflects separate scanner components; deductions across components are not all added together.')
  calculation.style.marginTop = '16px'
  addText(calculation, 'Applicable local URL deductions are aggregated within URL analysis. Eligible external-provider deductions are aggregated separately into a reputation score; page deductions form a page-inspection score. The final Safety Score is the lowest of the available component scores.', 'margin:9px 0 0;color:#cbd5e1;font-size:12px;line-height:1.6')
  addText(calculation, 'The response provides the final score and recorded finding deductions, but not intermediate component scores. They are not estimated here.', 'margin:8px 0 0;color:#94a3b8;font-size:12px;line-height:1.6')

  const notes = makeCard(content, 'Important Notes')
  notes.style.marginTop = '12px'
  addText(notes, 'The Safety Score is an indicator based on signals detected by the checks that ran. It is not a probability and does not guarantee that a website is safe. A higher score means fewer detected risk indicators, not zero risk.', 'margin:8px 0 0;color:#cbd5e1;font-size:12px;line-height:1.6')

  const actionSection = makeCard(content, 'Recommended Action')
  actionSection.style.marginTop = '12px'
  const recommendedAction = scan?.recommendations?.find((item) => typeof item === 'string' && item.trim()) ?? scoreDescription
  addText(actionSection, recommendedAction, `margin:8px 0 0;color:${palette.accent};font-size:12px;line-height:1.6`)

  overlay.addEventListener('click', (event) => { if (event.target === overlay) dismiss() })
  overlay.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') dismiss()
    if (event.key === 'Tab') {
      event.preventDefault()
      close.focus()
    }
  })
  overlay.appendChild(dialog)
  document.body.appendChild(overlay)
  close.focus()
}

function addBadge(anchor, scan) {
  if (anchor.dataset.threattrackMarked === 'true') return false

  anchor.dataset.threattrackMarked = 'true'
  anchor.dataset.threattrackStatus = scan.status

  const style = getResultStyle(scan)
  const badge = document.createElement('span')
  badge.className = 'threattrack-result-badge'
  badge.textContent = getScanLevel(scan) === 'content' ? style.label : `${style.label} ${scan.score}/100`
  badge.setAttribute('role', 'button')
  badge.setAttribute('tabindex', '0')
  badge.setAttribute('aria-label', `Show ${scan.status} classification and safety score details`)
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
  const openDetails = (event) => {
    event.preventDefault()
    event.stopPropagation()
    const normalized = normalizeCandidate(anchor.getAttribute('href'))
    if (!normalized) return
    showSafetyScoreModal(normalized, scan, badge)
  }
  badge.onclick = openDetails
  badge.onkeydown = (event) => { if (event.key === 'Enter' || event.key === ' ') openDetails(event) }

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
  const hasContentWarnings = scanStats.content > 0
  const hasGaps = scanStats.incomplete > 0 || scanStats.failed > 0
  const accentColor = scanStats.dangerous > 0 ? '#fecdd3' : hasRisk || hasContentWarnings || hasGaps ? '#fde68a' : '#6ee7b7'
  const borderColor =
    scanStats.dangerous > 0
      ? 'rgba(225,29,72,.45)'
      : hasRisk || hasContentWarnings || hasGaps
        ? 'rgba(245,158,11,.45)'
        : 'rgba(16,185,129,.45)'
  const statusText = searchConsentDecision === 'disabled'
    ? 'Search-result monitoring is off. Result URLs are not being sent for scanning.'
    : searchConsentDecision === 'preview-only'
      ? 'Search results are checked without saving scans to Scan History.'
    : searchConsentDecision === 'checking' || searchConsentDecision === 'missing'
      ? 'Choose whether to enable search-result monitoring.'
      : searchConsentDecision === 'unavailable'
        ? 'Privacy settings could not be checked. Search-result monitoring remains off.'
        : scanStats.checked === 0 && scanStats.failed === 0
      ? 'Scanning visible search results...'
      : scanStats.checked === 0
        ? 'Could not assess these results. Try scanning again.'
      : hasRisk
        ? `${riskyCount} risky search result${riskyCount === 1 ? '' : 's'} found`
        : hasContentWarnings
          ? `${scanStats.content} result${scanStats.content === 1 ? '' : 's'} with content warnings`
        : hasGaps ? 'Checked results appear safe. Some verification services or result scans were unavailable.' : 'Checked results appear safe based on available checks'

  banner.id = 'threattrack-search-status'
  banner.setAttribute('role', 'status')
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
  counts.textContent = `${scanStats.checked} checked - ${scanStats.safe + scanStats.incomplete} appear safe (${scanStats.incomplete} with limited verification) - ${scanStats.content} content warning - ${scanStats.failed} unavailable - ${scanStats.caution} caution - ${scanStats.dangerous} risk`
  counts.style.cssText = 'margin:8px 0 0;color:#e2e8f0;font-weight:700'

  const preferenceButton = document.createElement('button')
  preferenceButton.type = 'button'
  preferenceButton.textContent = ['accepted', 'preview-only', 'disabled'].includes(searchConsentDecision) ? 'Privacy settings' : 'Review privacy choices'
  preferenceButton.setAttribute('aria-label', 'Review or change Google Search monitoring privacy choices')
  preferenceButton.style.cssText = 'margin:8px 8px 0 0;border:1px solid #94a3b8;border-radius:6px;background:#1e293b;color:#f8fafc;padding:6px 9px;font:700 11px Arial,sans-serif;cursor:pointer'
  preferenceButton.addEventListener('click', () => showSearchConsentDialog(['accepted', 'preview-only', 'disabled'].includes(searchConsentDecision)))

  const privacyLink = document.createElement('a')
  privacyLink.href = getPrivacyNoticeUrl()
  privacyLink.target = '_blank'
  privacyLink.rel = 'noreferrer'
  privacyLink.textContent = 'Privacy notice'
  privacyLink.style.cssText = 'color:#99f6e4;font-weight:700'

  banner.append(title, body, counts, preferenceButton, privacyLink)
  if (!existing) document.body.appendChild(banner)
}

function getPrivacyNoticeUrl() {
  const url = new URL(APP_URL)
  url.searchParams.set('page', 'about')
  url.searchParams.set('section', 'privacy')
  return url.toString()
}

function showSearchConsentDialog(settingsMode = false) {
  if (document.getElementById('threattrack-search-consent')) return
  const overlay = document.createElement('div')
  overlay.id = 'threattrack-search-consent'
  overlay.setAttribute('role', 'dialog')
  overlay.setAttribute('aria-modal', 'true')
  overlay.setAttribute('aria-labelledby', 'threattrack-search-consent-title')
  overlay.style.cssText = 'all:initial;position:fixed;inset:0;z-index:2147483647;box-sizing:border-box;display:grid;place-items:center;background:rgba(2,6,23,.72);font-family:Arial,sans-serif;padding:16px'

  const panel = document.createElement('section')
  panel.style.cssText = 'box-sizing:border-box;width:min(560px,100%);max-height:calc(100vh - 32px);overflow:auto;border:1px solid #334155;border-radius:10px;background:#0f172a;box-shadow:0 28px 80px rgba(0,0,0,.5);color:#f8fafc;padding:22px'
  const eyebrow = document.createElement('p')
  eyebrow.textContent = 'PRIVACY AND CONSENT'
  eyebrow.style.cssText = 'margin:0;color:#5eead4;font:700 11px/1.4 Arial,sans-serif'
  const heading = document.createElement('h2')
  heading.id = 'threattrack-search-consent-title'
  heading.textContent = settingsMode ? 'Google Search monitoring settings' : 'Enable Google Search Results Monitoring?'
  heading.style.cssText = 'margin:7px 0 0;color:#fff;font:700 20px/1.3 Arial,sans-serif'
  const explanation = document.createElement('p')
  explanation.textContent = 'Tracking Threats checks eligible destination URLs from visible search results to detect phishing and suspicious links.'
  explanation.style.cssText = 'margin:10px 0 0;color:#cbd5e1;font:14px/1.55 Arial,sans-serif'
  const list = document.createElement('ul')
  list.style.cssText = 'margin:12px 0 0;padding-left:20px;color:#e2e8f0;font:13px/1.6 Arial,sans-serif'
  ;[
    'Saved monitoring sends eligible result URLs to the Tracking Threats backend to detect phishing and suspicious links. It saves the scan result and relevant URL information in Scan History under the service retention setting (30 days by default).',
    'Preview-only monitoring also sends eligible result URLs to the backend and may check URL or domain indicators with configured providers, but uses the existing non-persistent preview scan and does not create a Scan History record. See the Privacy Notice for service processing details.',
    'This feature does not collect the search terms on the search page or unrelated page content. A destination URL may itself contain query parameters.',
    'Choose saved monitoring, preview-only monitoring, or turn search-result monitoring off. You can change this preference later. Turning it off stops future search-result scans; it does not erase records already saved.',
  ].forEach((text) => {
    const item = document.createElement('li')
    item.textContent = text
    item.style.cssText = 'margin:6px 0'
    list.appendChild(item)
  })
  const privacyLink = document.createElement('a')
  privacyLink.href = getPrivacyNoticeUrl()
  privacyLink.target = '_blank'
  privacyLink.rel = 'noreferrer'
  privacyLink.textContent = 'Read the full Privacy Notice'
  privacyLink.style.cssText = 'display:inline-block;margin-top:10px;color:#5eead4;font:700 13px/1.4 Arial,sans-serif;text-decoration:underline'
  const actions = document.createElement('div')
  actions.style.cssText = 'display:flex;flex-wrap:wrap;gap:10px;margin-top:16px'
  let initialFocus = null
  const button = (text, primary, action) => {
    const control = document.createElement('button')
    control.type = 'button'
    control.textContent = text
    control.style.cssText = `border:1px solid ${primary ? '#0f766e' : '#64748b'};border-radius:7px;background:${primary ? '#0f766e' : 'transparent'};color:#f8fafc;padding:9px 13px;font:700 12px Arial,sans-serif;cursor:pointer`
    control.addEventListener('click', action)
    return control
  }

  if (settingsMode) {
    const keep = button('Keep current choice', true, () => overlay.remove())
    const save = button('Save scans to history', false, () => saveSearchMonitoringConsent('accepted', overlay))
    const preview = button('Scan without saving history', false, () => saveSearchMonitoringConsent('preview-only', overlay))
    const turnOff = button('Turn off all search scans', false, () => saveSearchMonitoringConsent('disabled', overlay))
    actions.append(keep, save, preview, turnOff)
    initialFocus = keep
  } else {
    const agreement = document.createElement('input')
    agreement.type = 'checkbox'
    agreement.id = 'threattrack-search-consent-agreement'
    const agreementLabel = document.createElement('label')
    agreementLabel.htmlFor = agreement.id
    agreementLabel.style.cssText = 'display:flex;align-items:flex-start;gap:9px;margin-top:14px;color:#e2e8f0;font:13px/1.5 Arial,sans-serif'
    const agreementText = document.createElement('span')
    agreementText.textContent = 'I agree to send eligible search-result URLs to Tracking Threats for scanning and to save scan records in Scan History under the stated retention policy.'
    agreementLabel.append(agreement, agreementText)
    const enable = button('Enable search monitoring', true, () => {
      if (agreement.checked) saveSearchMonitoringConsent('accepted', overlay)
    })
    enable.disabled = true
    agreement.addEventListener('change', () => { enable.disabled = !agreement.checked })
    const previewOnly = button('Scan without saving history', false, () => saveSearchMonitoringConsent('preview-only', overlay))
    const turnOff = button('Turn off all search scans', false, () => saveSearchMonitoringConsent('disabled', overlay))
    actions.append(agreementLabel, enable, previewOnly, turnOff)
    initialFocus = agreement
  }

  panel.append(eyebrow, heading, explanation, list, privacyLink, actions)
  overlay.appendChild(panel)
  document.body.appendChild(overlay)
  initialFocus?.focus()
}

function saveSearchMonitoringConsent(decision, overlay) {
  sendRuntimeMessage({ type: 'set-search-monitor-consent', decision }, (response, lastError) => {
    if (lastError || !response?.ok) {
      searchConsentDecision = 'unavailable'
      overlay.remove()
      showSearchStatus()
      return
    }
    overlay.remove()
    applySearchConsentDecision(response.decision, response.noticeVersion)
  })
}

function applySearchConsentDecision(decision, noticeVersion) {
  const previous = searchConsentDecision
  searchConsentDecision = noticeVersion === SEARCH_MONITOR_CONSENT_VERSION && ['accepted', 'preview-only', 'disabled'].includes(decision)
    ? decision
    : 'missing'
  if (previous !== searchConsentDecision) {
    searchConsentGeneration += 1
    window.clearTimeout(scanTimer)
    scannedResults.clear()
    latestResults.clear()
    riskyResults.clear()
    for (const key of Object.keys(scanStats)) scanStats[key] = 0
    document.getElementById('threattrack-search-consent')?.remove()
  }
  showSearchStatus()
  if (['accepted', 'preview-only'].includes(searchConsentDecision) && previous !== searchConsentDecision) scanGoogleResults()
  else if (searchConsentDecision === 'missing') showSearchConsentDialog()
}

function initializeSearchMonitoring() {
  sendRuntimeMessage({ type: 'get-search-monitor-consent' }, (response, lastError) => {
    if (lastError || !response?.ok) {
      searchConsentDecision = 'unavailable'
      showSearchStatus()
      return
    }
    applySearchConsentDecision(response.decision, response.noticeVersion)
  })
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
  const isSafe = getScanLevel(topScan) === 'safe'
  const isDangerous = topScan.status === 'Dangerous' || topScan.blocked
  const borderColor = isDangerous
    ? 'rgba(225,29,72,.45)'
    : isSafe
      ? 'rgba(16,185,129,.45)'
      : 'rgba(245,158,11,.45)'
  const accentColor = isDangerous ? '#fecdd3' : isSafe ? '#6ee7b7' : '#fde68a'
  const buttonColor = isDangerous ? '#9f1239' : isSafe ? '#065f46' : '#92400e'
  const statusText = getResultStyle(topScan).label

  popup.id = 'threattrack-google-warning'
  popup.style.cssText = [
    'position:fixed',
    'right:20px',
    'top:92px',
    'z-index:2147483647',
    'box-sizing:border-box',
    'width:min(360px,calc(100vw - 32px))',
    'max-height:calc(100vh - 112px)',
    'max-height:calc(100dvh - 112px)',
    'overflow-x:hidden',
    'overflow-y:auto',
    'overscroll-behavior:contain',
    '-webkit-overflow-scrolling:touch',
    'scrollbar-gutter:stable',
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
  title.innerHTML = `<strong style="display:block;font-size:14px;color:${accentColor}">Tracking Threats Result</strong><span style="color:#cbd5e1">${statusText} ? preview before opening this result.</span>`

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
  score.textContent = `Status: ${statusText} - ${getScoreText(topScan)}`
  score.style.cssText = `margin:8px 0 0;color:${accentColor};font-weight:700`
  popup.appendChild(score)
  appendScanDetailsDisclosure(popup, topScan)

  if (isSafe) {
    const safeText = document.createElement('p')
    safeText.textContent = 'No strong phishing indicators were found for this result.'
    safeText.style.cssText = 'margin:10px 0 0;color:#cbd5e1'
    popup.appendChild(safeText)
  }

  if (hasPiracyContent(topScan)) {
    const cautionText = document.createElement('p')
    cautionText.textContent = 'Blocked by the piracy-content policy. No strong phishing indicators were found, but download risk is unknown. Piracy-related sources may expose you to malware, fake mirrors, tampered files, and copyright risk.'
    cautionText.style.cssText = 'margin:10px 0 0;color:#fde68a;font-weight:700'
    popup.appendChild(cautionText)
  } else if (hasContentWarnings(topScan)) {
    const cautionText = document.createElement('p')
    cautionText.textContent = 'No strong phishing indicators were found, but a separate content-risk category needs review before continuing.'
    cautionText.style.cssText = 'margin:10px 0 0;color:#fde68a;font-weight:700'
    popup.appendChild(cautionText)
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
  setDetailsHref(details, topUrl, topScan)
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
      : level === 'caution' || level === 'content'
        ? '#fde68a'
        : '#6ee7b7'
  const warnings = scan.warningSigns?.slice(0, 4) ?? []
  const recommendations = scan.recommendations?.slice(0, 2) ?? []
  const piracyPolicyBlocked = hasPiracyContent(scan)
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
    'max-height:calc(100vh - 32px)',
    'max-height:calc(100dvh - 32px)',
    'overflow-x:hidden',
    'overflow-y:auto',
    'overscroll-behavior:contain',
    '-webkit-overflow-scrolling:touch',
    'scrollbar-gutter:stable',
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
  title.innerHTML = `<strong style="display:block;font-size:16px;color:${accentColor}">Tracking Threats Link Preview</strong><span style="color:#cbd5e1">${piracyPolicyBlocked ? 'This result is blocked by the piracy-content policy.' : 'Review this result before opening it.'}</span>`

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
  score.textContent = `Status: ${style.label} - ${getScoreText(scan)}`
  score.style.cssText = `margin:10px 0 0;color:${accentColor};font-weight:700`
  card.appendChild(score)
  appendThreatClassification(card, scan)
  appendScanDetailsDisclosure(card, scan, false, false)

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
  setDetailsHref(details, url, scan)
  details.target = '_blank'
  details.rel = 'noreferrer'
  details.textContent = 'Open details'
  details.style.cssText = createPreviewButton('Open details', 'primary').style.cssText

  const cancel = createPreviewButton('Stay on results')
  cancel.addEventListener('click', () => overlay.remove())

  actions.append(details, cancel)
  if (!piracyPolicyBlocked) {
    const continueButton = createPreviewButton('Continue anyway', 'danger')
    continueButton.addEventListener('click', () => {
      overlay.remove()
      if (anchor.target === '_blank') {
        window.open(url, '_blank', 'noopener,noreferrer')
        return
      }
      window.location.href = url
    })
    actions.appendChild(continueButton)
  }
  card.appendChild(actions)
  overlay.appendChild(card)
  document.body.appendChild(overlay)
}

function scanGoogleResults() {
  showSearchStatus()
  if (!['accepted', 'preview-only'].includes(searchConsentDecision)) {
    if (searchConsentDecision === 'missing') showSearchConsentDialog()
    return
  }
  const generation = searchConsentGeneration
  collectResultLinks().forEach((url) => {
    if (scannedResults.size >= MAX_RESULTS_PER_PAGE) return
    if (scannedResults.has(url)) return
    scannedResults.set(url, null)

    sendRuntimeMessage({
      type: searchConsentDecision === 'accepted' ? 'scan-search-result-url' : 'preview-candidate-url',
      url,
      reason: 'search-result-preview',
    }, (response, lastError) => {
      if (generation !== searchConsentGeneration || !['accepted', 'preview-only'].includes(searchConsentDecision)) return
      scannedResults.set(url, response?.scan ?? null)
      if (lastError || !response?.ok || !response.scan || response.scan.ok === false) {
        scanStats.failed += 1
        showSearchStatus()
        return
      }
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
    if (event.target.closest?.('.threattrack-result-badge')) return
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

showSearchStatus()
initializeSearchMonitoring()

const observer = new MutationObserver(scheduleScan)
observer.observe(document.body, { childList: true, subtree: true })

try {
  chrome.storage?.onChanged?.addListener((changes, areaName) => {
    if (areaName !== 'local' || !changes.trackingThreatsSearchConsent) return
    const consent = changes.trackingThreatsSearchConsent.newValue
    const decision = consent?.mode === 'saved' && consent.accepted === true
      ? 'accepted'
      : consent?.mode === 'preview-only' && consent.accepted === false
        ? 'preview-only'
        : consent?.mode === 'disabled' && consent.accepted === false
          ? 'disabled'
          : 'missing'
    applySearchConsentDecision(decision, consent?.noticeVersion)
  })
} catch (error) {
  if (!isExtensionContextInvalidated(error)) throw error
}
