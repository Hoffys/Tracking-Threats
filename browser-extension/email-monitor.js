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

function appendScanContext(parent, scan) {
  if (scan?.threatName && scan?.threatType) {
    const classification = document.createElement('div')
    classification.style.cssText = 'margin:10px 0 0;border:1px solid rgba(148,163,184,.35);border-radius:8px;padding:10px;color:#e2e8f0'
    const heading = document.createElement('strong')
    heading.textContent = `Threat name: ${scan.threatName}`
    heading.style.cssText = 'display:block;color:#f8fafc'
    const type = document.createElement('p')
    type.textContent = `Threat type: ${scan.threatType}${scan.confidence ? ` - Confidence: ${scan.confidence}` : ''}`
    type.style.cssText = 'margin:4px 0 0'
    const reason = document.createElement('p')
    reason.textContent = `Why: ${scan.whyDetected?.[0] || scan.warningSigns?.[0] || scan.summary || 'Review the scan evidence.'}`
    reason.style.cssText = 'margin:4px 0 0;color:#cbd5e1'
    classification.append(heading, type, reason)
    parent.appendChild(classification)
  }
  const detail = document.createElement('p')
  detail.textContent = [getCoverageText(scan), getCategoryText(scan), 'Rule-based score; not a calibrated probability.'].filter(Boolean).join(' ')
  detail.style.cssText = `margin:10px 0 0;color:${hasIncompleteChecks(scan) ? '#fde68a' : '#cbd5e1'}`
  parent.appendChild(detail)
}

function appendScanDetailsDisclosure(parent, scan) {
  const details = document.createElement('details')
  details.style.cssText = 'margin-top:10px;border-top:1px solid #263449;padding-top:8px'
  const summary = document.createElement('summary')
  summary.textContent = 'View more details'
  summary.style.cssText = 'color:#99f6e4;cursor:pointer;font:700 12px/1.4 Arial,sans-serif'
  details.appendChild(summary)
  appendScanContext(details, scan)
  parent.appendChild(details)
}

const MIN_EMAIL_TEXT_LENGTH = 40
const SCAN_DEBOUNCE_MS = 1400
const INBOX_SCAN_DEBOUNCE_MS = 2200
const INBOX_BATCH_SIZES = [10, 20, 30, 40, 50]
const DEFAULT_INBOX_BATCH_SIZE = 10
const MAX_INBOX_SCANS_IN_FLIGHT = 4
const APP_URL = TRACKING_THREATS_CONFIG.APP_URL
const EMAIL_CONSENT_KEY = 'trackingThreatsEmailConsent'
const EMAIL_BATCH_SIZE_KEY = 'trackingThreatsEmailBatchSize'
const EMAIL_CONSENT_VERSION = '2026.09'

let scanTimer = null
let inboxScanTimer = null
let lastScanKey = ''
let emailConsentGranted = false
let emailObserver = null
let inboxBatchNumber = 1
let inboxBatchStart = 0
let inboxBatchSize = DEFAULT_INBOX_BATCH_SIZE
let inboxBatchLimit = inboxBatchSize
let inboxAttempts = 0
let inboxPending = 0
let inboxPaused = false
let inboxWaitingForRows = false
let inboxGeneration = 0
const inboxScanKeys = new Set()
const inboxResults = []
const inboxStats = {
  checked: 0,
  safe: 0,
  incomplete: 0,
  caution: 0,
  dangerous: 0,
  content: 0,
  failed: 0,
}

function getPrivacyNoticeUrl() {
  const url = new URL(APP_URL)
  url.searchParams.set('page', 'about')
  url.searchParams.set('section', 'privacy')
  return url.toString()
}

async function readEmailConsent() {
  const stored = await chrome.storage.local.get(EMAIL_CONSENT_KEY)
  const consent = stored[EMAIL_CONSENT_KEY]
  if (consent?.noticeVersion !== EMAIL_CONSENT_VERSION) return 'missing'
  return consent.accepted === true ? 'accepted' : 'declined'
}

async function saveEmailConsent(accepted) {
  await chrome.storage.local.set({
    [EMAIL_CONSENT_KEY]: {
      accepted,
      noticeVersion: EMAIL_CONSENT_VERSION,
      updatedAt: new Date().toISOString(),
    },
  })
}

function normalizeInboxBatchSize(value) {
  const size = Number(value)
  return INBOX_BATCH_SIZES.includes(size) ? size : DEFAULT_INBOX_BATCH_SIZE
}

async function readInboxBatchSize() {
  const stored = await chrome.storage.local.get(EMAIL_BATCH_SIZE_KEY)
  return normalizeInboxBatchSize(stored[EMAIL_BATCH_SIZE_KEY])
}

function setInboxBatchSize(value, persist = true) {
  inboxBatchSize = normalizeInboxBatchSize(value)
  if (inboxPaused || inboxAttempts === inboxBatchStart) {
    inboxBatchLimit = inboxBatchStart + inboxBatchSize
  }
  if (persist) {
    chrome.storage.local.set({ [EMAIL_BATCH_SIZE_KEY]: inboxBatchSize }).catch(() => {})
  }
  return inboxBatchSize
}

function createInboxBatchSizeSelect(onChange = () => {}) {
  const select = document.createElement('select')
  select.setAttribute('aria-label', 'Emails to scan per batch')
  select.style.cssText = 'border:1px solid #475569;border-radius:6px;background:#111827;color:#f8fafc;cursor:pointer;font:700 11px Arial,sans-serif;padding:7px 9px'
  INBOX_BATCH_SIZES.forEach((size) => {
    const option = document.createElement('option')
    option.value = String(size)
    option.textContent = `${size} emails`
    select.appendChild(option)
  })
  select.value = String(inboxBatchSize)
  select.addEventListener('change', () => {
    setInboxBatchSize(select.value)
    onChange(inboxBatchSize)
  })
  return select
}

function clearEmailMonitorUi() {
  document.getElementById('threattrack-email-consent')?.remove()
  document.getElementById('threattrack-email-consent-disabled')?.remove()
  document.getElementById('threattrack-email-warning')?.remove()
  document.getElementById('threattrack-inbox-status')?.remove()
  document.getElementById('threattrack-inbox-review')?.remove()
  document.querySelectorAll('.threattrack-inbox-label').forEach((label) => label.remove())
  document.querySelectorAll('[data-threattrack-risk]').forEach((row) => {
    row.style.boxShadow = row.dataset.threattrackOriginalBoxShadow ?? ''
    row.style.backgroundColor = row.dataset.threattrackOriginalBackground ?? ''
    delete row.dataset.threattrackRisk
    delete row.dataset.threattrackLevel
    delete row.dataset.threattrackOriginalBoxShadow
    delete row.dataset.threattrackOriginalBackground
  })
}

function stopEmailMonitoring() {
  emailConsentGranted = false
  inboxGeneration += 1
  window.clearTimeout(scanTimer)
  window.clearTimeout(inboxScanTimer)
  emailObserver?.disconnect()
  emailObserver = null
  lastScanKey = ''
  inboxScanKeys.clear()
  inboxResults.length = 0
  inboxBatchNumber = 1
  inboxBatchStart = 0
  inboxBatchLimit = inboxBatchSize
  inboxAttempts = 0
  inboxPending = 0
  inboxPaused = false
  inboxWaitingForRows = false
  Object.keys(inboxStats).forEach((key) => {
    inboxStats[key] = 0
  })
  clearEmailMonitorUi()
}

async function disableEmailMonitoring() {
  await saveEmailConsent(false)
  stopEmailMonitoring()
  showEmailScanningDisabled()
}

function createTurnOffButton() {
  const button = document.createElement('button')
  button.type = 'button'
  button.textContent = 'Turn off'
  button.title = 'Withdraw consent and stop email scanning'
  button.style.cssText = [
    'border:1px solid rgba(255,255,255,.22)',
    'border-radius:6px',
    'background:transparent',
    'color:#f8fafc',
    'cursor:pointer',
    'font:700 11px Arial,sans-serif',
    'padding:5px 8px',
  ].join(';')
  button.addEventListener('click', () => {
    disableEmailMonitoring().catch(() => {})
  })
  return button
}

function showEmailScanningDisabled() {
  if (document.getElementById('threattrack-email-consent-disabled')) return

  const notice = document.createElement('aside')
  notice.id = 'threattrack-email-consent-disabled'
  notice.style.cssText = [
    'all:initial',
    'position:fixed',
    'right:20px',
    'bottom:20px',
    'z-index:2147483647',
    'box-sizing:border-box',
    'display:flex',
    'align-items:center',
    'gap:10px',
    'width:min(360px,calc(100vw - 32px))',
    'border:1px solid #334155',
    'border-radius:8px',
    'background:#0f172a',
    'box-shadow:0 16px 45px rgba(0,0,0,.35)',
    'color:#e2e8f0',
    'font:13px/1.4 Arial,sans-serif',
    'padding:12px',
  ].join(';')

  const text = document.createElement('span')
  text.textContent = 'Tracking Threats email scanning is off.'
  text.style.cssText = 'flex:1'

  const enable = document.createElement('button')
  enable.type = 'button'
  enable.textContent = 'Review and enable'
  enable.style.cssText = [
    'border:0',
    'border-radius:6px',
    'background:#0d9488',
    'color:white',
    'cursor:pointer',
    'font:700 12px Arial,sans-serif',
    'padding:8px 10px',
  ].join(';')
  enable.addEventListener('click', () => {
    notice.remove()
    showEmailConsentDialog()
  })

  notice.append(text, enable)
  document.body.appendChild(notice)
}

function showEmailConsentDialog() {
  if (document.getElementById('threattrack-email-consent')) return
  document.getElementById('threattrack-email-consent-disabled')?.remove()

  const overlay = document.createElement('div')
  overlay.id = 'threattrack-email-consent'
  overlay.setAttribute('role', 'dialog')
  overlay.setAttribute('aria-modal', 'true')
  overlay.setAttribute('aria-labelledby', 'threattrack-email-consent-title')
  overlay.style.cssText = [
    'all:initial',
    'position:fixed',
    'inset:0',
    'z-index:2147483647',
    'box-sizing:border-box',
    'display:grid',
    'place-items:center',
    'background:rgba(2,6,23,.72)',
    'font-family:Arial,sans-serif',
    'padding:16px',
  ].join(';')

  const panel = document.createElement('section')
  panel.style.cssText = [
    'box-sizing:border-box',
    'width:min(560px,100%)',
    'max-height:calc(100vh - 32px)',
    'overflow:auto',
    'border:1px solid #334155',
    'border-radius:8px',
    'background:#0f172a',
    'box-shadow:0 28px 80px rgba(0,0,0,.5)',
    'color:#f8fafc',
    'padding:22px',
  ].join(';')

  const eyebrow = document.createElement('p')
  eyebrow.textContent = 'CONFIDENTIALITY AND CONSENT'
  eyebrow.style.cssText = 'margin:0;color:#5eead4;font:700 11px/1.4 Arial,sans-serif'

  const title = document.createElement('h2')
  title.id = 'threattrack-email-consent-title'
  title.textContent = 'Enable email phishing scanning?'
  title.style.cssText = 'margin:7px 0 0;color:#fff;font:700 21px/1.3 Arial,sans-serif'

  const intro = document.createElement('p')
  intro.textContent =
    'Tracking Threats will not inspect or send email content until you provide consent.'
  intro.style.cssText = 'margin:10px 0 0;color:#cbd5e1;font:14px/1.55 Arial,sans-serif'

  const list = document.createElement('ul')
  list.style.cssText = 'margin:14px 0 0;padding-left:20px;color:#e2e8f0;font:13px/1.6 Arial,sans-serif'
  ;[
    'The extension checks the visible sender, subject, message text, links, and Gmail inbox previews. You choose 10, 20, 30, 40, or 50 messages per batch.',
    'This information is sent securely to the Tracking Threats backend for automated phishing analysis.',
    'Production does not retain raw email bodies. Redacted results and evidence are retained for up to 30 days.',
    'Consent applies to supported webmail opened in this browser. You can turn scanning off at any time.',
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
  privacyLink.style.cssText =
    'display:inline-block;margin-top:12px;color:#5eead4;font:700 13px/1.4 Arial,sans-serif;text-decoration:underline'

  const batchField = document.createElement('label')
  batchField.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:16px;border:1px solid #334155;border-radius:8px;background:#111827;color:#e2e8f0;font:700 13px/1.4 Arial,sans-serif;padding:12px'
  const batchText = document.createElement('span')
  batchText.textContent = 'Emails to scan per batch'
  const batchSelect = createInboxBatchSizeSelect()
  batchField.append(batchText, batchSelect)

  const agreementLabel = document.createElement('label')
  agreementLabel.style.cssText = [
    'display:flex',
    'align-items:flex-start',
    'gap:10px',
    'margin-top:16px',
    'border:1px solid #334155',
    'border-radius:8px',
    'background:#111827',
    'color:#f1f5f9',
    'font:13px/1.5 Arial,sans-serif',
    'padding:12px',
    'cursor:pointer',
  ].join(';')
  const agreement = document.createElement('input')
  agreement.type = 'checkbox'
  agreement.style.cssText = 'width:17px;height:17px;margin:1px 0 0;accent-color:#14b8a6;flex:none'
  const agreementText = document.createElement('span')
  agreementText.textContent =
    'I understand what email data will be processed and I authorize this browser to scan it.'
  agreementLabel.append(agreement, agreementText)

  const actions = document.createElement('div')
  actions.style.cssText = 'display:flex;justify-content:flex-end;gap:10px;margin-top:18px;flex-wrap:wrap'

  const decline = document.createElement('button')
  decline.type = 'button'
  decline.textContent = 'Not now'
  decline.style.cssText = [
    'border:1px solid #475569',
    'border-radius:7px',
    'background:transparent',
    'color:#e2e8f0',
    'cursor:pointer',
    'font:700 13px Arial,sans-serif',
    'padding:10px 14px',
  ].join(';')

  const accept = document.createElement('button')
  accept.type = 'button'
  accept.disabled = true
  accept.textContent = 'I Agree and Enable Email Scanning'
  accept.style.cssText = [
    'border:0',
    'border-radius:7px',
    'background:#0d9488',
    'color:white',
    'font:700 13px Arial,sans-serif',
    'padding:10px 14px',
    'opacity:.45',
    'cursor:not-allowed',
  ].join(';')

  agreement.addEventListener('change', () => {
    accept.disabled = !agreement.checked
    accept.style.opacity = agreement.checked ? '1' : '.45'
    accept.style.cursor = agreement.checked ? 'pointer' : 'not-allowed'
  })
  decline.addEventListener('click', () => {
    saveEmailConsent(false)
      .catch(() => {})
      .finally(() => {
        overlay.remove()
        showEmailScanningDisabled()
      })
  })
  accept.addEventListener('click', () => {
    if (!agreement.checked) return
    saveEmailConsent(true)
      .then(() => {
        overlay.remove()
        startEmailMonitoring()
      })
      .catch(() => {})
  })

  actions.append(decline, accept)
  panel.append(eyebrow, title, intro, list, privacyLink, batchField, agreementLabel, actions)
  overlay.appendChild(panel)
  document.body.appendChild(overlay)
  agreement.focus()
}

function cleanText(value = '') {
  return value.replace(/\s+/g, ' ').trim()
}

function isVisible(element) {
  const rect = element.getBoundingClientRect()
  return rect.width > 0 && rect.height > 0
}

function getVisibleText(selector) {
  const element = Array.from(document.querySelectorAll(selector)).find((item) => {
    return isVisible(item)
  })
  return cleanText(element?.textContent ?? '')
}

function getVisibleAttribute(selector, attribute) {
  const element = Array.from(document.querySelectorAll(selector))
    .filter(isVisible)
    .at(-1)
  return cleanText(element?.getAttribute(attribute) ?? '')
}

function getVisibleElements(selectors) {
  return selectors.flatMap((selector) =>
    Array.from(document.querySelectorAll(selector)).filter((element) => {
      return isVisible(element) && cleanText(element.textContent).length > 0
    }),
  )
}

function getVisibleLinks(elements) {
  return [
    ...new Set(
      elements
        .flatMap((element) => Array.from(element.querySelectorAll('a[href]')))
        .map((anchor) => anchor.href)
        .filter((href) => /^https?:\/\//i.test(href)),
    ),
  ]
}

function getTextWithLinks(element) {
  if (!element) return ''
  const text = cleanText(element.textContent ?? '')
  const links = getVisibleLinks([element])
  if (links.length === 0) return text
  return `${text}\n\nVisible links:\n${links.join('\n')}`
}

function getBodyFromSelectors(selectors) {
  const elements = getVisibleElements(selectors)
  if (elements.length > 0) return getTextWithLinks(elements.at(-1))
  return getTextWithLinks(getLargestVisibleElement(selectors))
}

function getLargestVisibleElement(selectors) {
  return selectors
    .flatMap((selector) => Array.from(document.querySelectorAll(selector)))
    .map((element) => {
      const rect = element.getBoundingClientRect()
      return {
        element,
        text: cleanText(element.textContent ?? ''),
        area: rect.width * rect.height,
        visible: isVisible(element),
      }
    })
    .filter((item) => item.visible && item.text.length > 0)
    .sort((left, right) => right.text.length + right.area - (left.text.length + left.area))[0]
    ?.element
}

function getGmailEmail() {
  return {
    sender:
      getVisibleAttribute('.gD[email]', 'email') ||
      getVisibleText('.gD') ||
      getVisibleText('.go'),
    subject: getVisibleText('h2.hP') || getVisibleText('[data-thread-perm-id] h2'),
    body: getBodyFromSelectors([
      '.a3s.aiL',
      '.adn.ads .a3s',
      'div[role="listitem"] .a3s',
      '.ii.gt',
      '[role="main"] .a3s',
    ]),
  }
}

function getGmailInboxRows() {
  return Array.from(document.querySelectorAll('tr.zA, div[role="main"] tr[role="link"]'))
    .filter(isVisible)
    .filter((row) => {
      const email = getGmailInboxEmail(row)
      return email.subject || email.body
    })
}

function getGmailInboxRowKey(row, email) {
  const threadId = row.getAttribute('data-legacy-thread-id') ||
    row.getAttribute('data-thread-id') || row.getAttribute('data-thread-perm-id') || row.id
  return threadId ? `thread:${threadId}` : `preview:${getScanKey(email)}`
}

function getRowText(row, selector) {
  return cleanText(row.querySelector(selector)?.textContent ?? '')
}

function getRowAttribute(row, selector, attribute) {
  return cleanText(row.querySelector(selector)?.getAttribute(attribute) ?? '')
}

function getGmailInboxEmail(row) {
  const sender =
    getRowAttribute(row, '.yX.xY .yP[email], .yW .yP[email], [email]', 'email') ||
    getRowAttribute(row, '.yX.xY .yP[name], .yW .yP[name]', 'name') ||
    getRowText(row, '.yX.xY, .yW')
  const subject = getRowText(row, '.bog, .y6 span[id]')
  const snippet = getRowText(row, '.y2')
  const link = row.querySelector('a[href]')?.href ?? ''

  return {
    sender,
    subject,
    body: [snippet, link ? `Email row link: ${link}` : ''].filter(Boolean).join('\n'),
  }
}

function getInboxBadgeStyle(scan) {
  const level = getScanLevel(scan)
  if (level === 'dangerous') {
    return {
      text: 'PHISHING RISK',
      border: 'rgba(225,29,72,.65)',
      background: '#ffe4e6',
      color: '#9f1239',
      rowBackground: 'rgba(225,29,72,.12)',
    }
  }
  if (level === 'caution') {
    return {
      text: 'CAUTION',
      border: 'rgba(245,158,11,.7)',
      background: '#fef3c7',
      color: '#92400e',
      rowBackground: 'rgba(245,158,11,.12)',
    }
  }
  if (level === 'content') {
    return {
      text: hasPiracyContent(scan) ? 'DOWNLOAD RISK UNKNOWN' : 'CONTENT WARNING',
      border: 'rgba(245,158,11,.7)',
      background: '#fef3c7',
      color: '#92400e',
      rowBackground: 'rgba(245,158,11,.12)',
    }
  }
  return {
    text: 'APPEARS SAFE',
    border: 'rgba(16,185,129,.55)',
    background: '#ccfbf1',
    color: '#065f46',
    rowBackground: 'rgba(16,185,129,.08)',
  }
}

function markGmailInboxRow(row, scan) {
  const style = getInboxBadgeStyle(scan)
  const existing = row.querySelector('.threattrack-inbox-label')
  if (!existing) {
    row.dataset.threattrackOriginalBoxShadow = row.style.boxShadow
    row.dataset.threattrackOriginalBackground = row.style.backgroundColor
  }
  const label = existing ?? document.createElement('span')
  label.className = 'threattrack-inbox-label'
  label.textContent = `${style.text} ${scan.score}/100`
  label.title = [getStatusLabel(scan.status, scan.coverage, scan.categories), getCoverageText(scan), getCategoryText(scan), 'Rule-based score; not a probability.'].filter(Boolean).join(' ')
  label.style.cssText = [
    'all:initial',
    'box-sizing:border-box',
    'display:inline-flex',
    'align-items:center',
    'min-height:20px',
    'margin-left:8px',
    `border:1px solid ${style.border}`,
    'border-radius:999px',
    `background:${style.background}`,
    `color:${style.color}`,
    'font:700 11px/18px Arial,sans-serif',
    'padding:0 8px',
    'white-space:nowrap',
    'vertical-align:middle',
    'cursor:pointer',
  ].join(';')
  label.onclick = (event) => {
    event.preventDefault()
    event.stopPropagation()
    const rowEmail = getGmailInboxEmail(row)
    const scanTarget = scan.target || rowEmail.sender || rowEmail.subject
    chrome.runtime.sendMessage({ type: 'get-linked-app-url' }, (response) => {
      const appUrl =
        chrome.runtime.lastError || !response?.ok || !response.appUrl ? APP_URL : response.appUrl
      window.open(getDetailsUrl(scanTarget, appUrl), '_blank', 'noopener,noreferrer')
    })
  }

  const subjectContainer =
    row.querySelector('.bog')?.parentElement ||
    row.querySelector('.y6') ||
    row.querySelector('td[role="gridcell"]:last-child') ||
    row

  if (!existing) subjectContainer.appendChild(label)
  row.style.boxShadow = `inset 4px 0 0 ${style.color}`
  row.style.backgroundColor = style.rowBackground
  row.dataset.threattrackRisk = scan.status
}

function showInboxStatus() {
  if (!emailConsentGranted || window.location.hostname !== 'mail.google.com') return

  const existing = document.getElementById('threattrack-inbox-status')
  const banner = existing ?? document.createElement('aside')
  const riskyCount = inboxStats.caution + inboxStats.dangerous
  const hasRisk = riskyCount > 0
  const hasContentWarnings = inboxStats.content > 0
  const hasGaps = inboxStats.incomplete > 0 || inboxStats.failed > 0
  const batchProgress = inboxAttempts - inboxBatchStart
  const accentColor = inboxStats.dangerous > 0 ? '#fecdd3' : hasRisk || hasContentWarnings || hasGaps ? '#fde68a' : '#6ee7b7'
  const borderColor =
    inboxStats.dangerous > 0
      ? 'rgba(225,29,72,.45)'
      : hasRisk || hasContentWarnings || hasGaps
        ? 'rgba(245,158,11,.45)'
        : 'rgba(16,185,129,.45)'
  let statusText = 'Scanning visible Gmail messages...'
  if (inboxPaused) {
    statusText = `Batch ${inboxBatchNumber} finished. Inbox scanning is paused.`
  } else if (inboxWaitingForRows) {
    statusText = 'No new visible messages. Open another Gmail page to continue.'
  } else if (inboxPending === 0 && hasRisk) {
    statusText = `${riskyCount} risky email${riskyCount === 1 ? '' : 's'} found`
  } else if (inboxPending === 0 && hasContentWarnings) {
    statusText = `${inboxStats.content} email${inboxStats.content === 1 ? '' : 's'} with content warnings`
  } else if (inboxPending === 0 && inboxStats.checked === 0 && inboxStats.failed > 0) {
    statusText = 'Could not assess these messages. Try scanning again.'
  } else if (inboxPending === 0 && hasGaps) {
    statusText = 'Checked messages appear safe. Some verification services or message scans were unavailable.'
  } else if (inboxPending === 0 && inboxStats.checked > 0) {
    statusText = 'Checked messages appear safe based on available checks.'
  }

  banner.id = 'threattrack-inbox-status'
  banner.setAttribute('role', 'status')
  banner.style.cssText = [
    'position:fixed',
    'right:20px',
    'top:92px',
    'z-index:2147483646',
    'box-sizing:border-box',
    'width:min(330px,calc(100vw - 32px))',
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
  title.textContent = 'Tracking Threats Gmail Monitor'
  title.style.cssText = `display:block;font-size:14px;color:${accentColor}`

  const body = document.createElement('p')
  body.textContent = statusText
  body.style.cssText = 'margin:6px 0 0;color:#cbd5e1'

  const counts = document.createElement('p')
  counts.textContent = `Batch ${inboxBatchNumber}: ${batchProgress}/${inboxBatchSize} attempted - ${inboxPending} pending`
  counts.style.cssText = 'margin:8px 0 0;color:#e2e8f0;font-weight:700'

  const totals = document.createElement('p')
  totals.textContent = `${inboxStats.checked} checked - ${inboxStats.safe + inboxStats.incomplete} appear safe (${inboxStats.incomplete} with limited verification) - ${inboxStats.content} content warning - ${inboxStats.caution} caution - ${inboxStats.dangerous} risk - ${inboxStats.failed} failed`
  totals.style.cssText = 'margin:3px 0 0;color:#cbd5e1;font-size:11px'

  const batchControls = document.createElement('div')
  batchControls.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:10px;border-top:1px solid #263449;padding-top:10px'
  const batchLabel = document.createElement('span')
  batchLabel.textContent = inboxPaused ? 'Next batch size' : 'Batch size'
  batchLabel.style.cssText = 'color:#cbd5e1;font:700 11px Arial,sans-serif'
  const batchSelect = createInboxBatchSizeSelect(() => showInboxStatus())
  batchControls.append(batchLabel, batchSelect)

  const header = document.createElement('div')
  header.style.cssText = 'display:flex;align-items:start;justify-content:space-between;gap:10px'
  header.append(title, createTurnOffButton())

  banner.append(header, body, counts, totals, batchControls)
  if (inboxResults.length > 0) {
    const actions = document.createElement('div')
    actions.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;margin-top:10px'
    const review = document.createElement('button')
    review.type = 'button'
    review.textContent = 'Review scanned emails'
    review.style.cssText = 'border:1px solid #475569;border-radius:6px;background:transparent;color:#f8fafc;cursor:pointer;font:700 11px Arial,sans-serif;padding:7px 9px'
    review.addEventListener('click', () => showInboxReview())
    actions.appendChild(review)
    if (inboxPaused) {
      const next = document.createElement('button')
      next.type = 'button'
      next.textContent = `Scan next ${inboxBatchSize}`
      next.style.cssText = 'border:0;border-radius:6px;background:#0d9488;color:#fff;cursor:pointer;font:700 11px Arial,sans-serif;padding:7px 9px'
      next.addEventListener('click', continueInboxBatch)
      actions.appendChild(next)
    }
    banner.appendChild(actions)
  }
  if (!existing) document.body.appendChild(banner)
}

function continueInboxBatch() {
  if (!emailConsentGranted || !inboxPaused) return
  inboxBatchNumber += 1
  inboxBatchStart = inboxAttempts
  inboxBatchLimit = inboxBatchStart + inboxBatchSize
  inboxPaused = false
  inboxWaitingForRows = false
  document.getElementById('threattrack-inbox-review')?.remove()
  scanGmailInbox()
}

function showInboxReview(selectedBatch = inboxBatchNumber) {
  if (!emailConsentGranted || window.location.hostname !== 'mail.google.com') return
  document.getElementById('threattrack-inbox-review')?.remove()

  const overlay = document.createElement('div')
  overlay.id = 'threattrack-inbox-review'
  overlay.setAttribute('role', 'dialog')
  overlay.setAttribute('aria-modal', 'true')
  overlay.setAttribute('aria-labelledby', 'threattrack-inbox-review-title')
  overlay.style.cssText = 'all:initial;position:fixed;inset:0;z-index:2147483647;display:grid;place-items:center;box-sizing:border-box;background:rgba(2,6,23,.76);font-family:Arial,sans-serif;padding:16px'

  const panel = document.createElement('section')
  panel.style.cssText = 'box-sizing:border-box;display:flex;flex-direction:column;width:min(680px,100%);max-height:calc(100vh - 32px);overflow:hidden;border:1px solid #334155;border-radius:14px;background:#0f172a;color:#f8fafc;box-shadow:0 28px 80px rgba(0,0,0,.55)'

  const entries = inboxResults.filter((result) => result.batch === selectedBatch)
  const failed = entries.filter((result) => result.failed).length
  const pending = entries.filter((result) => result.pending).length
  const checked = entries.length - failed - pending
  const safe = entries.filter((result) => result.level === 'safe' || result.level === 'incomplete').length
  const limited = entries.filter((result) => result.level === 'incomplete').length
  const needsReview = entries.filter((result) => ['content', 'caution', 'dangerous'].includes(result.level)).length

  const header = document.createElement('header')
  header.style.cssText = 'flex:none;border-bottom:1px solid #263449;padding:20px 22px 18px'

  const headingRow = document.createElement('div')
  headingRow.style.cssText = 'display:flex;align-items:flex-start;justify-content:space-between;gap:16px'

  const heading = document.createElement('div')
  heading.style.cssText = 'min-width:0'

  const eyebrow = document.createElement('p')
  eyebrow.textContent = `GMAIL INBOX  •  BATCH ${selectedBatch}`
  eyebrow.style.cssText = 'margin:0 0 5px;color:#5eead4;font:700 11px/1.4 Arial,sans-serif;letter-spacing:.08em'

  const title = document.createElement('h2')
  title.id = 'threattrack-inbox-review-title'
  title.textContent = 'Email scan results'
  title.style.cssText = 'margin:0;color:#fff;font:700 21px/1.3 Arial,sans-serif'

  const summary = document.createElement('p')
  summary.textContent = `${entries.length} message${entries.length === 1 ? '' : 's'} in this batch. Sender and subject stay in this browser tab.`
  summary.style.cssText = 'margin:6px 0 0;color:#aebdd0;font:13px/1.5 Arial,sans-serif'
  heading.append(eyebrow, title, summary)

  const closeIcon = document.createElement('button')
  closeIcon.type = 'button'
  closeIcon.textContent = '×'
  closeIcon.setAttribute('aria-label', 'Close email scan results')
  closeIcon.style.cssText = 'flex:none;display:grid;place-items:center;width:32px;height:32px;border:1px solid #3b4a61;border-radius:8px;background:#172033;color:#cbd5e1;cursor:pointer;font:400 22px/1 Arial,sans-serif;padding:0'
  closeIcon.addEventListener('click', () => overlay.remove())
  headingRow.append(heading, closeIcon)
  header.appendChild(headingRow)

  const metrics = document.createElement('div')
  metrics.style.cssText = 'display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:16px'
  const metricData = [
    ['Checked', checked, '#e2e8f0'],
    ['No warnings', safe, '#6ee7b7'],
    ['Warnings', needsReview, needsReview > 0 ? '#fde68a' : '#94a3b8'],
    ['Failed', failed, failed > 0 ? '#fca5a5' : '#94a3b8'],
  ]
  metricData.forEach(([label, value, color]) => {
    const metric = document.createElement('div')
    metric.style.cssText = 'min-width:0;border:1px solid #2f3d52;border-radius:9px;background:#111c2e;padding:9px 10px'
    const valueText = document.createElement('strong')
    valueText.textContent = String(value)
    valueText.style.cssText = `display:block;color:${color};font:700 16px/1.2 Arial,sans-serif`
    const labelText = document.createElement('span')
    labelText.textContent = label
    labelText.style.cssText = 'display:block;margin-top:3px;color:#94a3b8;font:11px/1.3 Arial,sans-serif;white-space:nowrap;overflow:hidden;text-overflow:ellipsis'
    metric.append(valueText, labelText)
    metrics.appendChild(metric)
  })
  header.appendChild(metrics)
  if (limited > 0) {
    const limitedNote = document.createElement('p')
    limitedNote.textContent = `${limited} result${limited === 1 ? '' : 's'} had limited verification. Expand a message to review what was unavailable.`
    limitedNote.style.cssText = 'margin:10px 0 0;border-left:3px solid #f59e0b;border-radius:3px;background:rgba(245,158,11,.08);color:#fde68a;font:11px/1.45 Arial,sans-serif;padding:7px 9px'
    header.appendChild(limitedNote)
  }
  panel.appendChild(header)

  const content = document.createElement('div')
  content.style.cssText = 'min-height:0;display:flex;flex:1;flex-direction:column;padding:14px 22px 0'

  const listHeader = document.createElement('div')
  listHeader.style.cssText = 'flex:none;display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px'
  const listTitle = document.createElement('strong')
  listTitle.textContent = 'Scanned messages'
  listTitle.style.cssText = 'color:#e2e8f0;font:700 12px/1.4 Arial,sans-serif'
  listHeader.appendChild(listTitle)

  if (inboxBatchNumber > 1) {
    const batchSelect = document.createElement('select')
    batchSelect.setAttribute('aria-label', 'Choose scan batch')
    batchSelect.style.cssText = 'box-sizing:border-box;max-width:150px;border:1px solid #475569;border-radius:7px;background:#111827;color:#f8fafc;font:12px Arial,sans-serif;padding:7px 30px 7px 9px'
    for (let batch = 1; batch <= inboxBatchNumber; batch += 1) {
      const option = document.createElement('option')
      option.value = String(batch)
      option.textContent = `Batch ${batch}`
      batchSelect.appendChild(option)
    }
    batchSelect.value = String(selectedBatch)
    batchSelect.addEventListener('change', () => showInboxReview(Number(batchSelect.value)))
    listHeader.appendChild(batchSelect)
  }
  content.appendChild(listHeader)

  const list = document.createElement('ul')
  list.style.cssText = 'list-style:none;min-height:0;margin:0;padding:0 4px 14px 0;overflow:auto'
  entries.forEach((result) => {
    const item = document.createElement('li')
    item.style.cssText = 'box-sizing:border-box;margin:0 0 8px;border:1px solid #2c3b50;border-radius:10px;background:#111c2e;padding:12px 13px'
    const itemTop = document.createElement('div')
    itemTop.style.cssText = 'display:flex;align-items:flex-start;justify-content:space-between;gap:14px'
    const identity = document.createElement('div')
    identity.style.cssText = 'min-width:0;overflow-wrap:anywhere'
    const subject = document.createElement('strong')
    subject.textContent = result.subject || '(No subject)'
    subject.style.cssText = 'display:block;color:#f8fafc;font:700 13px/1.4 Arial,sans-serif'
    const sender = document.createElement('span')
    sender.textContent = result.sender || 'Unknown sender'
    sender.style.cssText = 'display:block;margin-top:3px;color:#94a3b8;font:12px/1.4 Arial,sans-serif'
    identity.append(subject, sender)
    const status = document.createElement('span')
    const isWarning = ['incomplete', 'caution', 'content'].includes(result.level)
    const statusColor = result.failed
      ? '#fca5a5'
      : result.pending
        ? '#cbd5e1'
        : result.level === 'dangerous'
          ? '#fecdd3'
          : isWarning
            ? '#fde68a'
            : '#6ee7b7'
    const statusBackground = result.failed || result.level === 'dangerous'
      ? 'rgba(190,24,93,.15)'
      : isWarning
        ? 'rgba(245,158,11,.12)'
        : result.pending
          ? 'rgba(148,163,184,.10)'
          : 'rgba(16,185,129,.12)'
    status.textContent = result.pending
      ? 'Scanning'
      : result.failed
        ? 'Failed'
        : `${getStatusLabel(result.status, result.coverage, result.categories)}  •  ${result.score}/100`
    status.style.cssText = `flex:none;border:1px solid ${statusColor}55;border-radius:999px;background:${statusBackground};color:${statusColor};font:700 11px/1.3 Arial,sans-serif;padding:6px 9px;white-space:nowrap`
    itemTop.append(identity, status)
    item.appendChild(itemTop)

    if (result.pending || result.failed) {
      const stateText = document.createElement('p')
      stateText.textContent = result.pending
        ? 'This message is still being checked.'
        : 'This message could not be assessed. Try scanning it again later.'
      stateText.style.cssText = `margin:9px 0 0;color:${result.failed ? '#fca5a5' : '#cbd5e1'};font:12px/1.45 Arial,sans-serif`
      item.appendChild(stateText)
    } else {
      const details = document.createElement('details')
      details.style.cssText = 'margin-top:9px;border-top:1px solid #263449;padding-top:8px'
      const detailsToggle = document.createElement('summary')
      detailsToggle.textContent = 'View scan details'
      detailsToggle.style.cssText = 'color:#99f6e4;cursor:pointer;font:700 11px/1.4 Arial,sans-serif'
      const context = document.createElement('p')
      context.textContent = [getCoverageText(result), getCategoryText(result)].filter(Boolean).join(' ')
      context.style.cssText = 'margin:8px 0 1px;color:#cbd5e1;font:12px/1.5 Arial,sans-serif'
      details.append(detailsToggle, context)
      item.appendChild(details)
    }
    list.appendChild(item)
  })
  content.appendChild(list)
  panel.appendChild(content)

  const footer = document.createElement('footer')
  footer.style.cssText = 'flex:none;display:flex;align-items:center;justify-content:space-between;gap:16px;border-top:1px solid #263449;background:#0c1424;padding:14px 22px;flex-wrap:wrap'
  const scope = document.createElement('p')
  scope.textContent = inboxPaused
    ? 'Inbox preview scanning is paused. Opened emails are still covered by your consent.'
    : 'Scanning continues while this Gmail tab remains open.'
  scope.style.cssText = 'flex:1;min-width:220px;margin:0;color:#94a3b8;font:11px/1.45 Arial,sans-serif'

  const actions = document.createElement('div')
  actions.style.cssText = 'display:flex;justify-content:flex-end;gap:9px;flex-wrap:wrap'
  const close = document.createElement('button')
  close.type = 'button'
  close.textContent = inboxPaused ? 'Done for now' : 'Close'
  close.style.cssText = 'border:1px solid #475569;border-radius:8px;background:transparent;color:#f8fafc;cursor:pointer;font:700 12px Arial,sans-serif;padding:9px 13px'
  close.addEventListener('click', () => overlay.remove())
  actions.appendChild(close)
  if (inboxPaused) {
    const batchSelect = createInboxBatchSizeSelect((size) => {
      next.textContent = `Scan next ${size}`
    })
    const next = document.createElement('button')
    next.type = 'button'
    next.textContent = `Scan next ${inboxBatchSize}`
    next.style.cssText = 'border:0;border-radius:8px;background:#0d9488;color:#fff;cursor:pointer;font:700 12px Arial,sans-serif;padding:9px 13px'
    next.addEventListener('click', continueInboxBatch)
    actions.append(batchSelect, next)
  }
  footer.append(scope, actions)
  panel.appendChild(footer)
  overlay.appendChild(panel)
  overlay.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') overlay.remove()
  })
  document.body.appendChild(overlay)
  close.focus()
}

function getOutlookEmail() {
  return {
    sender:
      getVisibleText('[data-testid="message-header"] [title*="@"]') ||
      getVisibleText('[aria-label*="From"]') ||
      getVisibleText('[role="heading"]'),
    subject: getVisibleText('[role="heading"][aria-level="1"]') || getVisibleText('h1'),
    body: getBodyFromSelectors([
      '[aria-label="Message body"]',
      '[role="document"]',
      '[data-testid="messageBodyContent"]',
      '[data-testid*="message-body"]',
      'main',
    ]),
  }
}

function getYahooEmail() {
  return {
    sender:
      getVisibleText('[data-test-id="message-view-from"]') ||
      getVisibleText('[data-test-id="message-from"]'),
    subject:
      getVisibleText('[data-test-id="message-view-subject"]') ||
      getVisibleText('[data-test-id="message-subject"]') ||
      getVisibleText('h1'),
    body: getBodyFromSelectors([
      '[data-test-id="message-view-body"]',
      '[data-test-id="message-body"]',
      '[role="document"]',
      'main',
    ]),
  }
}

function getProtonEmail() {
  return {
    sender:
      getVisibleText('[data-testid*="sender"]') ||
      getVisibleText('[class*="sender"]') ||
      getVisibleText('[title*="@"]'),
    subject:
      getVisibleText('[data-testid*="subject"]') ||
      getVisibleText('[class*="subject"]') ||
      getVisibleText('h1'),
    body: getBodyFromSelectors([
      '[data-testid*="message-content"]',
      '[class*="message-content"]',
      '[role="document"]',
      'article',
    ]),
  }
}

function getIcloudEmail() {
  return {
    sender:
      getVisibleText('[aria-label*="From"]') ||
      getVisibleText('[class*="sender"]') ||
      getVisibleText('[title*="@"]'),
    subject:
      getVisibleText('[aria-label*="Subject"]') ||
      getVisibleText('[class*="subject"]') ||
      getVisibleText('h1'),
    body: getBodyFromSelectors([
      '[aria-label="Message body"]',
      '[class*="message-body"]',
      '[role="document"]',
      'article',
    ]),
  }
}

function getGenericWebmailEmail() {
  return {
    sender:
      getVisibleText('[aria-label*="From"]') ||
      getVisibleText('[data-testid*="sender"]') ||
      getVisibleText('[data-test-id*="sender"]') ||
      getVisibleText('[class*="sender"]') ||
      getVisibleText('[title*="@"]'),
    subject:
      getVisibleText('[aria-label*="Subject"]') ||
      getVisibleText('[data-testid*="subject"]') ||
      getVisibleText('[data-test-id*="subject"]') ||
      getVisibleText('[class*="subject"]') ||
      getVisibleText('h1, h2'),
    body: getBodyFromSelectors([
      '[aria-label="Message body"]',
      '[data-testid*="message-body"]',
      '[data-test-id*="message-body"]',
      '[data-testid*="message-content"]',
      '[class*="message-body"]',
      '[class*="message-content"]',
      '[role="document"]',
      'article',
    ]),
  }
}

function getOpenedEmail() {
  const host = window.location.hostname
  if (host === 'mail.google.com') return getGmailEmail()
  if (host.includes('outlook.')) return getOutlookEmail()
  if (host.includes('mail.yahoo.')) return getYahooEmail()
  if (host.includes('proton.')) return getProtonEmail()
  if (host.includes('icloud.com')) return getIcloudEmail()
  if (host.includes('zoho.') || host.includes('mail.com') || host.includes('aol.com')) {
    return getGenericWebmailEmail()
  }

  return {
    sender: '',
    subject: getVisibleText('h1, [role="heading"]'),
    body: getBodyFromSelectors(['main, article, [role="main"]']),
  }
}

function getScanKey(email) {
  return JSON.stringify({
    sender: email.sender,
    subject: email.subject,
    body: email.body.slice(0, 2000),
  })
}

function isTrackingThreatsReport(email) {
  return email.subject.trim().toLowerCase().startsWith('[tracking threats]')
}

function isRiskyScan(scan) {
  return scan?.status === 'Dangerous' || scan?.status === 'Suspicious' || scan?.blocked
}

function hasPiracyContent(scan) {
  return scan?.categories?.includes('piracy-content') === true
}

function hasContentWarnings(scan) {
  return scan?.categories?.some((category) => typeof category === 'string' && category.endsWith('-content')) === true
}

function getScanLevel(scan) {
  if (scan?.status === 'Dangerous' || scan?.blocked) return 'dangerous'
  if (scan?.status === 'Suspicious') return 'caution'
  if (scan?.status === 'Safe' && hasContentWarnings(scan)) return 'content'
  if (hasIncompleteChecks(scan)) return 'incomplete'
  return 'safe'
}

function getStatusLabel(status, coverage, categories = []) {
  if (status === 'Safe' && categories.includes('piracy-content')) return 'Download risk unknown'
  if (status === 'Safe' && categories.some((category) => typeof category === 'string' && category.endsWith('-content'))) return 'Content warning'
  if (status === 'Safe' && hasIncompleteChecks({ coverage })) return 'No warning found - limited check'
  if (status === 'Safe') return 'No warning found'
  if (status === 'Dangerous') return 'Risk detected'
  return status === 'Suspicious' ? 'Caution' : status
}

function getDetailsUrl(target, appUrl = APP_URL) {
  const url = new URL(appUrl)
  url.searchParams.set('page', 'history')
  if (target) url.searchParams.set('blocked', target)
  return url.toString()
}

function setDetailsHref(anchor, target) {
  anchor.href = getDetailsUrl(target)
  chrome.runtime.sendMessage({ type: 'get-linked-app-url' }, (response) => {
    if (chrome.runtime.lastError || !response?.ok || !response.appUrl) return
    anchor.href = getDetailsUrl(target, response.appUrl)
  })
}

function showEmailWarning(scan, email) {
  const existing = document.getElementById('threattrack-email-warning')
  const banner = existing ?? document.createElement('aside')
  const warnings = scan.warningSigns?.slice(0, 4) ?? []
  const recommendations = scan.recommendations?.slice(0, 2) ?? []
  const isContentWarning = scan.status === 'Safe' && hasContentWarnings(scan)
  const isSafe = scan.status === 'Safe' && !isContentWarning
  const isDangerous = scan.status === 'Dangerous' || scan.blocked
  const borderColor = isDangerous ? 'rgba(225,29,72,.45)' : isSafe ? 'rgba(16,185,129,.45)' : 'rgba(245,158,11,.45)'
  const accentColor = isDangerous ? '#fecdd3' : isSafe ? '#6ee7b7' : '#fde68a'
  const buttonColor = isSafe ? '#065f46' : isContentWarning ? '#92400e' : '#9f1239'
  const titleText = isSafe ? 'Tracking Threats Email Scan' : isContentWarning ? 'Tracking Threats Content Warning' : 'Tracking Threats Email Warning'
  const scanTarget = scan.target || email.sender || email.subject || 'Opened email'

  banner.id = 'threattrack-email-warning'
  banner.style.cssText = [
    'position:fixed',
    'right:20px',
    'top:92px',
    'z-index:2147483647',
    'box-sizing:border-box',
    'width:min(380px,calc(100vw - 32px))',
    `border:1px solid ${borderColor}`,
    'border-radius:8px',
    'background:#111827',
    'color:#f8fafc',
    'box-shadow:0 18px 50px rgba(0,0,0,.42)',
    'font:13px/1.45 Arial,sans-serif',
    'padding:14px',
  ].join(';')

  banner.innerHTML = ''

  const header = document.createElement('div')
  header.style.cssText = 'display:flex;align-items:start;justify-content:space-between;gap:12px'

  const title = document.createElement('div')
  title.innerHTML = `<strong style="display:block;font-size:14px;color:${accentColor}">${titleText}</strong><span style="color:#cbd5e1">Scanned after your consent.</span>`

  const close = document.createElement('button')
  close.type = 'button'
  close.textContent = 'x'
  close.setAttribute('aria-label', 'Dismiss email warning')
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
  close.addEventListener('click', () => banner.remove())

  header.append(title, close)
  banner.appendChild(header)

  const target = document.createElement('p')
  target.textContent = email.sender || email.subject || 'Opened email'
  target.style.cssText = 'margin:10px 0 0;color:#e2e8f0;overflow-wrap:anywhere'
  banner.appendChild(target)

  const score = document.createElement('p')
  score.textContent = `Status: ${getStatusLabel(scan.status, scan.coverage, scan.categories)} - Rule-based score ${scan.score}/100`
  score.style.cssText = `margin:8px 0 0;color:${accentColor};font-weight:700`
  banner.appendChild(score)
  appendScanDetailsDisclosure(banner, scan)

  if (isSafe) {
    const safeText = document.createElement('p')
    safeText.textContent = 'No strong phishing indicators were found in this opened email.'
    safeText.style.cssText = 'margin:10px 0 0;color:#cbd5e1'
    banner.appendChild(safeText)
  }

  if (isContentWarning) {
    const cautionText = document.createElement('p')
    cautionText.textContent = hasPiracyContent(scan)
      ? 'No strong phishing indicators were found, but download risk is unknown. Piracy-related sources may expose you to malware, fake mirrors, tampered files, and copyright risk.'
      : 'No strong phishing indicators were found, but a separate content-risk category needs review before continuing.'
    cautionText.style.cssText = 'margin:10px 0 0;color:#fde68a;font-weight:700'
    banner.appendChild(cautionText)
  }

  if (warnings.length > 0) {
    const list = document.createElement('ul')
    list.style.cssText = 'margin:10px 0 0;padding-left:18px;color:#f1f5f9'
    warnings.forEach((warning) => {
      const item = document.createElement('li')
      item.textContent = warning
      list.appendChild(item)
    })
    banner.appendChild(list)
  }

  if (recommendations.length > 0) {
    const recommendation = document.createElement('p')
    recommendation.textContent = recommendations[0]
    recommendation.style.cssText = 'margin:10px 0 0;color:#cbd5e1'
    banner.appendChild(recommendation)
  }

  const details = document.createElement('a')
  setDetailsHref(details, scanTarget)
  details.target = '_blank'
  details.rel = 'noreferrer'
  details.textContent = 'Open scan details'
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
  banner.appendChild(details)

  const turnOff = createTurnOffButton()
  turnOff.style.marginLeft = '8px'
  banner.appendChild(turnOff)

  if (!existing) document.body.appendChild(banner)
}

function showInboxRiskWarning(scan, email) {
  showEmailWarning(scan, {
    sender: email.sender,
    subject: email.subject || 'Inbox email',
    body: email.body,
  })
}

function scanGmailInboxRow(row) {
  if (!emailConsentGranted || inboxPaused || inboxAttempts >= inboxBatchLimit) return false
  const email = getGmailInboxEmail(row)
  const content = `${email.subject}\n${email.body}`.trim()
  if (
    (!email.sender && !email.subject) ||
    isTrackingThreatsReport(email) ||
    content.length < 12
  ) {
    return false
  }

  const scanKey = getGmailInboxRowKey(row, email)
  if (inboxScanKeys.has(scanKey)) return false
  inboxScanKeys.add(scanKey)
  inboxAttempts += 1
  inboxPending += 1
  inboxWaitingForRows = false
  const generation = inboxGeneration
  const result = {
    batch: inboxBatchNumber,
    sender: email.sender,
    subject: email.subject,
    pending: true,
  }
  inboxResults.push(result)

  chrome.runtime.sendMessage(
    {
      type: 'scan-email-content',
      email,
    },
    (response) => {
      if (!emailConsentGranted || generation !== inboxGeneration) return
      inboxPending -= 1
      result.pending = false
      if (chrome.runtime.lastError || !response?.ok || !response.scan) {
        result.failed = true
        inboxStats.failed += 1
      } else {
        inboxStats.checked += 1
        const nextLevel = getScanLevel(response.scan)
        inboxStats[nextLevel] += 1
        result.level = nextLevel
        result.status = response.scan.status
        result.score = response.scan.score
        result.coverage = response.scan.coverage
        result.categories = response.scan.categories
        result.categoryWarnings = response.scan.categoryWarnings
        row.dataset.threattrackLevel = nextLevel
        markGmailInboxRow(row, response.scan)
        if (isRiskyScan(response.scan)) showInboxRiskWarning(response.scan, email)
      }
      showInboxStatus()
      scanGmailInbox()
    },
  )
  return true
}

function scanGmailInbox() {
  if (!emailConsentGranted || window.location.hostname !== 'mail.google.com') return
  if (inboxPaused) return
  let started = 0
  for (const row of getGmailInboxRows()) {
    if (inboxPending >= MAX_INBOX_SCANS_IN_FLIGHT || inboxAttempts >= inboxBatchLimit) break
    if (scanGmailInboxRow(row)) started += 1
  }
  const visibleRowsExhausted = started === 0 && inboxAttempts > inboxBatchStart
  if (inboxPending === 0 && (inboxAttempts >= inboxBatchLimit || visibleRowsExhausted)) {
    inboxPaused = true
    showInboxStatus()
    showInboxReview()
    return
  }
  inboxWaitingForRows = started === 0 && inboxPending === 0
  showInboxStatus()
}

function scanOpenedEmail() {
  if (!emailConsentGranted) return
  const email = getOpenedEmail()
  const content = `${email.subject}\n${email.body}`.trim()
  if (
    (!email.sender && !email.subject) ||
    isTrackingThreatsReport(email) ||
    content.length < MIN_EMAIL_TEXT_LENGTH
  ) {
    return
  }

  const scanKey = getScanKey(email)
  if (scanKey === lastScanKey) return
  lastScanKey = scanKey

  chrome.runtime.sendMessage(
    {
      type: 'scan-email-content',
      email,
    },
    (response) => {
      if (!emailConsentGranted) return
      if (chrome.runtime.lastError) return
      if (!response?.ok || !response.scan) return
      showEmailWarning(response.scan, email)
    },
  )
}

function scheduleScan() {
  if (!emailConsentGranted) return
  window.clearTimeout(scanTimer)
  scanTimer = window.setTimeout(scanOpenedEmail, SCAN_DEBOUNCE_MS)
}

function scheduleInboxScan() {
  if (!emailConsentGranted) return
  window.clearTimeout(inboxScanTimer)
  inboxScanTimer = window.setTimeout(scanGmailInbox, INBOX_SCAN_DEBOUNCE_MS)
}

function scheduleEmailChecks() {
  if (!emailConsentGranted) return
  scheduleScan()
  scheduleInboxScan()
}

function startEmailMonitoring() {
  if (emailConsentGranted && emailObserver) return
  emailConsentGranted = true
  document.getElementById('threattrack-email-consent-disabled')?.remove()
  showInboxStatus()
  scheduleEmailChecks()
  emailObserver = new MutationObserver(scheduleEmailChecks)
  emailObserver.observe(document.body, { childList: true, subtree: true })
}

Promise.all([readEmailConsent(), readInboxBatchSize()])
  .then(([decision, batchSize]) => {
    setInboxBatchSize(batchSize, false)
    if (decision === 'accepted') startEmailMonitoring()
    else if (decision === 'declined') showEmailScanningDisabled()
    else showEmailConsentDialog()
  })
  .catch(() => showEmailConsentDialog())
