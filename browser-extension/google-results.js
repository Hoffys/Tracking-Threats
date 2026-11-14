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
  const accent = dangerous ? '#fda4af' : suspicious ? '#fcd34d' : '#6ee7b7'
  const style = getResultStyle(scan)
  const overlay = document.createElement('div')
  overlay.id = 'threattrack-safety-score-modal'
  overlay.setAttribute('role', 'presentation')
  overlay.style.cssText = 'position:fixed;inset:0;z-index:2147483647;box-sizing:border-box;display:flex;align-items:center;justify-content:center;background:rgba(2,6,23,.66);padding:16px'

  const dialog = document.createElement('section')
  dialog.setAttribute('role', 'dialog')
  dialog.setAttribute('aria-modal', 'true')
  dialog.setAttribute('aria-labelledby', 'threattrack-score-title')
  dialog.tabIndex = -1
  dialog.style.cssText = `box-sizing:border-box;width:min(600px,100%);max-height:calc(100vh - 32px);max-height:calc(100dvh - 32px);overflow:auto;overscroll-behavior:contain;-webkit-overflow-scrolling:touch;border:1px solid ${style.border};border-radius:12px;background:#111827;color:#f8fafc;box-shadow:0 24px 80px rgba(0,0,0,.55);font:14px/1.5 Arial,sans-serif;padding:18px`

  const addText = (parent, text, css = '') => {
    const node = document.createElement('p')
    node.textContent = text
    node.style.cssText = css
    parent.appendChild(node)
    return node
  }
  const addSection = (titleText) => {
    const section = document.createElement('section')
    section.style.cssText = 'margin-top:16px;border-top:1px solid #334155;padding-top:12px'
    const heading = document.createElement('h3')
    heading.textContent = titleText
    heading.style.cssText = 'margin:0;color:#f8fafc;font-size:14px'
    section.appendChild(heading)
    dialog.appendChild(section)
    return section
  }

  const header = document.createElement('div')
  header.style.cssText = 'display:flex;align-items:flex-start;justify-content:space-between;gap:12px'
  const title = document.createElement('h2')
  title.id = 'threattrack-score-title'
  title.textContent = 'Website Safety Details'
  title.style.cssText = `margin:0;color:${accent};font-size:18px`
  const close = document.createElement('button')
  close.type = 'button'
  close.textContent = 'Close'
  close.setAttribute('aria-label', 'Close safety score details')
  close.style.cssText = 'flex:0 0 auto;border:1px solid #475569;border-radius:7px;background:#1e293b;color:#f8fafc;padding:7px 10px;font:700 12px Arial,sans-serif;cursor:pointer'
  const dismiss = () => { overlay.remove(); returnFocus?.focus?.() }
  close.addEventListener('click', dismiss)
  header.append(title, close)
  dialog.appendChild(header)

  addText(dialog, url, 'margin:12px 0 0;overflow-wrap:anywhere;color:#cbd5e1')
  addText(dialog, `URL Security Classification: ${status} · Safety Score ${scan?.score ?? 'Unavailable'}/100`, `margin:8px 0 0;color:${accent};font-size:16px;font-weight:700`)

  const explanation = dangerous
    ? 'The scan found threat indicators for this website.'
    : suspicious
      ? 'The scan found warning signs. Review them carefully and use caution before continuing.'
      : status === 'Safe'
        ? 'Fewer risk indicators were detected in the checks that ran. A Safe result does not guarantee that a website is harmless.'
        : 'The scan classification is unavailable.'
  addText(dialog, explanation, 'margin:8px 0 0;color:#e2e8f0')

  if (dangerous) {
    const why = addSection('Why is this website dangerous?')
    addText(why, scan?.summary || 'The scan classified this website as Dangerous based on the findings below.', 'margin:7px 0 0;color:#fecdd3')
  }

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
  const hasContentRisk = contentCategories.length > 0 || categoryWarnings.length > 0
  if (hasContentRisk) {
    const content = addSection('Piracy / Content Risk')
    if (categoryWarnings.length > 0) {
      categoryWarnings.forEach((warning) => addText(content, warning, 'margin:7px 0 0;color:#fde68a'))
    } else {
      addText(content, 'Content category indicators were recorded, but the scanner did not provide their warning text.', 'margin:7px 0 0;color:#fde68a')
    }
    if (piracyRisk) {
      addText(content, 'This is a separate content/download risk warning, not a phishing or malware finding. Downloaded files were not assessed by this URL score.', 'margin:7px 0 0;color:#cbd5e1')
    } else {
      addText(content, 'Content category warnings are separate from the URL phishing and malware classification.', 'margin:7px 0 0;color:#cbd5e1')
    }
  }

  const localRules = (details?.findings ?? []).filter((finding) => Number(finding?.deduction ?? 0) > 0)
  const pageFindings = (details?.pageInspection?.findings ?? []).filter((finding) => typeof finding === 'string' && finding.trim())
  const hasStructuredLocalFindings = Array.isArray(details?.findings) || Array.isArray(details?.pageInspection?.findings)
  const local = addSection('Local security findings')
  if (localRules.length === 0 && pageFindings.length === 0) {
    const localMessage = hasStructuredLocalFindings
      ? 'No Security Findings Detected'
      : 'Local security finding details are unavailable for this scan.'
    addText(local, localMessage, 'margin:7px 0 0;color:#cbd5e1')
  } else {
    localRules.forEach((finding) => {
      const card = document.createElement('div')
      card.style.cssText = 'margin-top:9px;border:1px solid #334155;border-radius:8px;padding:10px'
      const name = document.createElement('strong')
      name.textContent = finding.label || finding.code || 'Triggered local rule'
      name.style.cssText = 'display:block;color:#f8fafc'
      card.appendChild(name)
      addText(card, `Why it triggered: ${finding.label || 'The scanner recorded this rule as triggered.'}`, 'margin:5px 0 0;color:#cbd5e1')
      if (finding.evidence && typeof finding.evidence === 'object' && Object.keys(finding.evidence).length > 0) {
        addText(card, `Evidence found: ${JSON.stringify(finding.evidence)}`, 'margin:5px 0 0;color:#cbd5e1;overflow-wrap:anywhere')
      } else {
        addText(card, 'Evidence found: The scanner did not provide additional evidence details.', 'margin:5px 0 0;color:#cbd5e1')
      }
      local.appendChild(card)
    })
    pageFindings.forEach((finding) => {
      const inspection = details?.pageInspection
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
      const evidence = inspection
        ? Object.fromEntries(evidenceKeys.filter((key) => inspection[key] !== undefined).map((key) => [key, inspection[key]]))
        : null
      const card = document.createElement('div')
      card.style.cssText = 'margin-top:9px;border:1px solid #334155;border-radius:8px;padding:10px'
      const name = document.createElement('strong')
      name.textContent = finding
      name.style.cssText = 'display:block;color:#f8fafc'
      card.appendChild(name)
      addText(card, `Why it triggered: ${finding}`, 'margin:5px 0 0;color:#cbd5e1')
      addText(card, Object.keys(evidence ?? {}).length ? `Evidence found: ${JSON.stringify(evidence)}` : 'Evidence found: The system could not retrieve additional page evidence details.', 'margin:5px 0 0;color:#cbd5e1;overflow-wrap:anywhere')
      local.appendChild(card)
    })
  }

  const providers = Array.isArray(details?.threatIntel) &&
      (details.threatIntel.length > 0 || !Array.isArray(scan?.threatIntel))
    ? details.threatIntel
    : Array.isArray(scan?.threatIntel) ? scan.threatIntel : null
  const externalProviders = (providers ?? []).filter((provider) => !['Page inspection', 'Rendered page inspection'].includes(provider?.provider))
  const intel = addSection('External threat intelligence')
  if (providers === null) {
    addText(intel, 'Threat intelligence provider details were not included in the scan response.', 'margin:7px 0 0;color:#cbd5e1')
  } else if (externalProviders.length === 0) {
    addText(intel, 'No external provider findings were returned in this scan. Provider-level results were not listed.', 'margin:7px 0 0;color:#cbd5e1')
  } else {
    externalProviders.forEach((provider) => {
      const unavailable = provider?.checked !== true || provider?.error || provider?.skipped
      const state = provider?.found === true && !unavailable ? 'Finding reported' : unavailable ? 'Unavailable' : 'No finding reported'
      const explanation = state === 'Unavailable'
        ? ''
        : state === 'Finding reported' && provider?.warning ? ` — ${provider.warning}` : ''
      addText(intel, `${provider?.provider || 'Threat intelligence provider'}: ${state}${explanation}`, 'margin:7px 0 0;color:#cbd5e1;overflow-wrap:anywhere')
    })
  }

  const actionSection = addSection('Recommended action')
  const action = scan?.recommendations?.find((item) => typeof item === 'string' && item.trim()) ??
    (dangerous ? 'Avoid visiting this website. Do not enter personal information.' : suspicious ? 'Use caution and verify the website through a trusted source before continuing.' : status === 'Safe' ? 'No strong risk indicators were detected in the checks that ran; continue with normal caution.' : 'Treat the result as unverified until a scan is available.')
  addText(actionSection, action, `margin:7px 0 0;color:${accent}`)

  overlay.addEventListener('click', (event) => { if (event.target === overlay) dismiss() })
  overlay.addEventListener('keydown', (event) => { if (event.key === 'Escape') dismiss() })
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
