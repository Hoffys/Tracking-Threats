const MIN_EMAIL_TEXT_LENGTH = 40
const SCAN_DEBOUNCE_MS = 1400
const INBOX_SCAN_DEBOUNCE_MS = 2200
const MAX_INBOX_ROWS_PER_PASS = 50
const APP_URL = TRACKING_THREATS_CONFIG.APP_URL
const EMAIL_CONSENT_KEY = 'trackingThreatsEmailConsent'
const EMAIL_CONSENT_VERSION = '2026.09'

let scanTimer = null
let inboxScanTimer = null
let lastScanKey = ''
let emailConsentGranted = false
let emailObserver = null
const inboxScanKeys = new Set()
const inboxStats = {
  checked: 0,
  safe: 0,
  caution: 0,
  dangerous: 0,
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

function clearEmailMonitorUi() {
  document.getElementById('threattrack-email-consent')?.remove()
  document.getElementById('threattrack-email-consent-disabled')?.remove()
  document.getElementById('threattrack-email-warning')?.remove()
  document.getElementById('threattrack-inbox-status')?.remove()
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
  window.clearTimeout(scanTimer)
  window.clearTimeout(inboxScanTimer)
  emailObserver?.disconnect()
  emailObserver = null
  lastScanKey = ''
  inboxScanKeys.clear()
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
    'The extension checks the visible sender, subject, message text, links, and up to 50 visible Gmail inbox previews.',
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
  panel.append(eyebrow, title, intro, list, privacyLink, agreementLabel, actions)
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
    .slice(0, MAX_INBOX_ROWS_PER_PASS)
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
  return {
    text: 'SAFE',
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
  label.title = 'Tracking Threats detected phishing indicators in this email.'
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
  const accentColor = inboxStats.dangerous > 0 ? '#fecdd3' : hasRisk ? '#fde68a' : '#6ee7b7'
  const borderColor =
    inboxStats.dangerous > 0
      ? 'rgba(225,29,72,.45)'
      : hasRisk
        ? 'rgba(245,158,11,.45)'
        : 'rgba(16,185,129,.45)'
  const statusText =
    inboxStats.checked === 0
      ? 'Scanning visible Gmail inbox messages...'
      : hasRisk
        ? `${riskyCount} risky email${riskyCount === 1 ? '' : 's'} found`
        : 'No risky email found in visible inbox'

  banner.id = 'threattrack-inbox-status'
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
  counts.textContent = `${inboxStats.checked} checked - ${inboxStats.safe} safe - ${inboxStats.caution} caution - ${inboxStats.dangerous} risk`
  counts.style.cssText = 'margin:8px 0 0;color:#e2e8f0;font-weight:700'

  const header = document.createElement('div')
  header.style.cssText = 'display:flex;align-items:start;justify-content:space-between;gap:10px'
  header.append(title, createTurnOffButton())

  banner.append(header, body, counts)
  if (!existing) document.body.appendChild(banner)
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

function getScanLevel(scan) {
  if (scan?.status === 'Dangerous' || scan?.blocked) return 'dangerous'
  if (scan?.status === 'Suspicious') return 'caution'
  return 'safe'
}

function getStatusLabel(status) {
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
  const isSafe = scan.status === 'Safe'
  const borderColor = isSafe ? 'rgba(16,185,129,.45)' : 'rgba(225,29,72,.45)'
  const accentColor = isSafe ? '#6ee7b7' : '#fecdd3'
  const buttonColor = isSafe ? '#065f46' : '#9f1239'
  const titleText = isSafe ? 'Tracking Threats Email Scan' : 'Tracking Threats Email Warning'
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
  score.textContent = `Status: ${getStatusLabel(scan.status)} - Safety score ${scan.score}/100`
  score.style.cssText = `margin:8px 0 0;color:${accentColor};font-weight:700`
  banner.appendChild(score)

  if (isSafe) {
    const safeText = document.createElement('p')
    safeText.textContent = 'No strong phishing indicators were found in this opened email.'
    safeText.style.cssText = 'margin:10px 0 0;color:#cbd5e1'
    banner.appendChild(safeText)
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
  if (!emailConsentGranted) return
  const email = getGmailInboxEmail(row)
  const content = `${email.subject}\n${email.body}`.trim()
  if (
    (!email.sender && !email.subject) ||
    isTrackingThreatsReport(email) ||
    content.length < 12
  ) {
    return
  }

  const scanKey = getScanKey(email)
  if (inboxScanKeys.has(scanKey)) return
  inboxScanKeys.add(scanKey)

  chrome.runtime.sendMessage(
    {
      type: 'scan-email-content',
      email,
    },
    (response) => {
      if (!emailConsentGranted) return
      if (chrome.runtime.lastError || !response?.ok || !response.scan) return
      const previousLevel = row.dataset.threattrackLevel
      if (!previousLevel) {
        inboxStats.checked += 1
      } else if (inboxStats[previousLevel] > 0) {
        inboxStats[previousLevel] -= 1
      }
      const nextLevel = getScanLevel(response.scan)
      inboxStats[nextLevel] += 1
      row.dataset.threattrackLevel = nextLevel
      markGmailInboxRow(row, response.scan)
      showInboxStatus()
      if (isRiskyScan(response.scan)) showInboxRiskWarning(response.scan, email)
    },
  )
}

function scanGmailInbox() {
  if (!emailConsentGranted || window.location.hostname !== 'mail.google.com') return
  showInboxStatus()
  getGmailInboxRows().forEach(scanGmailInboxRow)
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
  scheduleEmailChecks()
  emailObserver = new MutationObserver(scheduleEmailChecks)
  emailObserver.observe(document.body, { childList: true, subtree: true })
}

readEmailConsent()
  .then((decision) => {
    if (decision === 'accepted') startEmailMonitoring()
    else if (decision === 'declined') showEmailScanningDisabled()
    else showEmailConsentDialog()
  })
  .catch(() => showEmailConsentDialog())
