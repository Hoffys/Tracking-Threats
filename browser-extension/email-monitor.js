const MIN_EMAIL_TEXT_LENGTH = 40
const SCAN_DEBOUNCE_MS = 1400
const INBOX_SCAN_DEBOUNCE_MS = 2200
const MAX_INBOX_ROWS_PER_PASS = 12
const APP_URL = TRACKING_THREATS_CONFIG.APP_URL

let scanTimer = null
let inboxScanTimer = null
let lastScanKey = ''
const inboxScanKeys = new Set()

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
  const dangerous = scan.status === 'Dangerous' || scan.blocked
  return {
    text: dangerous ? 'PHISHING RISK' : 'CAUTION',
    border: dangerous ? 'rgba(225,29,72,.65)' : 'rgba(245,158,11,.7)',
    background: dangerous ? '#ffe4e6' : '#fef3c7',
    color: dangerous ? '#9f1239' : '#92400e',
  }
}

function markGmailInboxRow(row, scan) {
  if (!isRiskyScan(scan)) return

  const style = getInboxBadgeStyle(scan)
  const existing = row.querySelector('.threattrack-inbox-label')
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
  row.style.backgroundColor =
    scan.status === 'Dangerous' || scan.blocked ? 'rgba(225,29,72,.12)' : 'rgba(245,158,11,.12)'
  row.dataset.threattrackRisk = scan.status
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
  title.innerHTML = `<strong style="display:block;font-size:14px;color:${accentColor}">${titleText}</strong><span style="color:#cbd5e1">Opened email scanned locally.</span>`

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
      if (chrome.runtime.lastError || !response?.ok || !response.scan) return
      markGmailInboxRow(row, response.scan)
      if (isRiskyScan(response.scan)) showInboxRiskWarning(response.scan, email)
    },
  )
}

function scanGmailInbox() {
  if (window.location.hostname !== 'mail.google.com') return
  getGmailInboxRows().forEach(scanGmailInboxRow)
}

function scanOpenedEmail() {
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
      if (chrome.runtime.lastError) return
      if (!response?.ok || !response.scan) return
      showEmailWarning(response.scan, email)
    },
  )
}

function scheduleScan() {
  window.clearTimeout(scanTimer)
  scanTimer = window.setTimeout(scanOpenedEmail, SCAN_DEBOUNCE_MS)
}

function scheduleInboxScan() {
  window.clearTimeout(inboxScanTimer)
  inboxScanTimer = window.setTimeout(scanGmailInbox, INBOX_SCAN_DEBOUNCE_MS)
}

function scheduleEmailChecks() {
  scheduleScan()
  scheduleInboxScan()
}

scheduleEmailChecks()

const observer = new MutationObserver(scheduleEmailChecks)
observer.observe(document.body, { childList: true, subtree: true })
