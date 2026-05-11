const MIN_EMAIL_TEXT_LENGTH = 40
const SCAN_DEBOUNCE_MS = 1400
const APP_URL = 'http://localhost:5173/'

let scanTimer = null
let lastScanKey = ''

function getVisibleText(selector) {
  const element = Array.from(document.querySelectorAll(selector)).find((item) => {
    const rect = item.getBoundingClientRect()
    return rect.width > 0 && rect.height > 0
  })
  return element?.textContent?.trim() ?? ''
}

function getLargestVisibleText(selectors) {
  return selectors
    .flatMap((selector) => Array.from(document.querySelectorAll(selector)))
    .map((element) => {
      const rect = element.getBoundingClientRect()
      return {
        element,
        text: element.textContent?.trim() ?? '',
        area: rect.width * rect.height,
        visible: rect.width > 0 && rect.height > 0,
      }
    })
    .filter((item) => item.visible && item.text.length > 0)
    .sort((left, right) => right.text.length + right.area - (left.text.length + left.area))[0]
    ?.text ?? ''
}

function getGmailEmail() {
  const bodies = Array.from(document.querySelectorAll('.a3s.aiL, .adn.ads .a3s, div[role="listitem"] .a3s, .ii.gt'))
    .filter((item) => {
      const rect = item.getBoundingClientRect()
      return rect.width > 0 && rect.height > 0 && item.textContent.trim().length > 0
    })
    .map((item) => item.textContent.trim())

  return {
    sender:
      document.querySelector('.gD[email]')?.getAttribute('email') ||
      getVisibleText('.gD') ||
      getVisibleText('.go'),
    subject: getVisibleText('h2.hP') || getVisibleText('[data-thread-perm-id] h2'),
    body:
      bodies.at(-1) ??
      getLargestVisibleText(['[role="main"] .a3s', '[role="main"] [dir="ltr"]', '[role="main"]']),
  }
}

function getOutlookEmail() {
  return {
    sender:
      getVisibleText('[data-testid="message-header"] [title*="@"]') ||
      getVisibleText('[aria-label*="From"]') ||
      getVisibleText('[role="heading"]'),
    subject: getVisibleText('[role="heading"][aria-level="1"]') || getVisibleText('h1'),
    body:
      getVisibleText('[aria-label="Message body"]') ||
      getVisibleText('[role="document"]') ||
      getVisibleText('main'),
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
    body:
      getVisibleText('[data-test-id="message-view-body"]') ||
      getVisibleText('[data-test-id="message-body"]') ||
      getVisibleText('main'),
  }
}

function getOpenedEmail() {
  const host = window.location.hostname
  if (host === 'mail.google.com') return getGmailEmail()
  if (host.includes('outlook.')) return getOutlookEmail()
  if (host.includes('mail.yahoo.')) return getYahooEmail()

  return {
    sender: '',
    subject: getVisibleText('h1, [role="heading"]'),
    body: getVisibleText('main, article, [role="main"]'),
  }
}

function getScanKey(email) {
  return JSON.stringify({
    sender: email.sender,
    subject: email.subject,
    body: email.body.slice(0, 2000),
  })
}

function isRiskyScan(scan) {
  return scan?.status === 'Dangerous' || scan?.status === 'Suspicious' || scan?.blocked
}

function getStatusLabel(status) {
  return status === 'Suspicious' ? 'Caution' : status
}

function getDetailsUrl(target) {
  const url = new URL(APP_URL)
  url.searchParams.set('page', 'history')
  if (target) url.searchParams.set('blocked', target)
  return url.toString()
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
  details.href = getDetailsUrl(email.sender || email.subject)
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

function scanOpenedEmail() {
  const email = getOpenedEmail()
  const content = `${email.subject}\n${email.body}`.trim()
  if (content.length < MIN_EMAIL_TEXT_LENGTH) return

  const scanKey = getScanKey(email)
  if (scanKey === lastScanKey) return
  lastScanKey = scanKey

  chrome.runtime.sendMessage(
    {
      type: 'scan-email-content',
      email,
    },
    (response) => {
      if (!response?.ok || !response.scan) return
      showEmailWarning(response.scan, email)
    },
  )
}

function scheduleScan() {
  window.clearTimeout(scanTimer)
  scanTimer = window.setTimeout(scanOpenedEmail, SCAN_DEBOUNCE_MS)
}

scheduleScan()

const observer = new MutationObserver(scheduleScan)
observer.observe(document.body, { childList: true, subtree: true })
