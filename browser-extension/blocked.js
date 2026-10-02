const params = new URLSearchParams(window.location.search)
const blockedHost = params.get('host') || ''
const APP_URL = TRACKING_THREATS_CONFIG.APP_URL

let blockedUrl = params.get('url') || ''
let blockedScanId = params.get('scan') || ''

function getUrlText(url = '', host = '') {
  try {
    const parsedUrl = new URL(url || `https://${host}`)
    return `${parsedUrl.hostname} ${parsedUrl.pathname} ${parsedUrl.search}`.toLowerCase()
  } catch {
    return `${url} ${host}`.toLowerCase()
  }
}

function inferThreatFromUrl(url = '', host = '') {
  const text = getUrlText(url, host)

  if (/torrent|pirate|crack|cracked|keygen|warez|fitgirl|dodi|elamigos|game3rb|gamedrive|gog-games|igg-games|igggames|kisskh|oceanofgames|ovagames|repack-games|steamrip|steamunlocked|online-fix|thepiratebay|repack|repacks/.test(text)) {
    return {
      threatName: 'Piracy-related content warning',
      threatType: 'Piracy or illegal download risk',
      primaryWarning: 'This site matches piracy, cracked software, torrent, or repack indicators.',
    }
  }

  if (/casino|gambl(e|ing)|betting?|sportsbook|slots?|jackpot|poker|roulette|baccarat|sabong|freebet/.test(text)) {
    return {
      threatName: 'Gambling-related content warning',
      threatType: 'Gambling or betting risk',
      primaryWarning: 'This site matches gambling, betting, or cash-out indicators.',
    }
  }

  if (/secure|security|verify|verification|account|accounts|login|signin|password|billing|wallet|claim|reward|promo|bonus|update/.test(text)) {
    return {
      threatName: 'Suspected credential phishing page',
      threatType: 'Phishing or credential theft risk',
      primaryWarning: 'This URL uses account, login, verification, or reward wording often used in phishing.',
    }
  }

  return {
    threatName: 'Dangerous website',
    threatType: 'Dangerous website risk',
    primaryWarning: 'The scanner found dangerous URL indicators.',
  }
}

function getDetailsUrl({ appUrl = APP_URL, url = '', host = '', scanId = '' } = {}) {
  const detailsUrl = new URL(APP_URL)
  detailsUrl.href = appUrl
  detailsUrl.searchParams.set('page', 'history')
  const target = url || host
  if (target) detailsUrl.searchParams.set('blocked', target)
  if (scanId) detailsUrl.searchParams.set('scan', scanId)
  return detailsUrl.toString()
}

function updateDetailsLink({ url = '', host = '', scanId = blockedScanId } = {}) {
  const detailsLink = document.getElementById('details-link')
  const historyStatus = document.getElementById('history-status')
  const retry = document.getElementById('retry-history')
  detailsLink.removeAttribute('href')
  detailsLink.setAttribute('aria-disabled', 'true')
  retry.hidden = true
  historyStatus.textContent = 'Connecting this result to your scan history...'
  chrome.runtime.sendMessage({ type: 'prepare-blocked-details', url: url || `https://${host}/`, scanId }, (response) => {
    const error = chrome.runtime.lastError
    if (error || !response?.ok || !response.scan?.id || !response.appUrl) {
      historyStatus.textContent = `History could not be synced: ${error?.message || response?.error || 'Extension unavailable'}. Retry when connected.`
      retry.hidden = false
      return
    }
    blockedScanId = response.scan.id
    const reason = response.scan.whyDetected?.[0] || response.scan.warningSigns?.[0] || response.scan.summary
    document.getElementById('threat-name').textContent = `Threat name: ${response.scan.threatName || 'Dangerous website'}`
    document.getElementById('threat-type').textContent = `Threat type: ${response.scan.threatType || 'Website risk'}`
    document.getElementById('threat-reason').textContent = reason || 'The scanner found dangerous URL indicators.'
    detailsLink.href = getDetailsUrl({ appUrl: response.appUrl, url, host, scanId: blockedScanId })
    detailsLink.removeAttribute('aria-disabled')
    historyStatus.textContent = `Saved in this browser's History and Live Monitor. Latest scan: ${response.scan.status}, safety score ${response.scan.score}/100.`
  })
}

function renderBlockedPage({
  url = '',
  host = '',
  status = 'Blocked',
  score = '0',
  threatName = '',
  threatType = '',
  primaryWarning = '',
  scanId = '',
}) {
  blockedUrl = url
  blockedScanId = scanId || blockedScanId
  const inferredThreat = inferThreatFromUrl(blockedUrl, host)
  const displayedThreatName = threatName || inferredThreat.threatName
  const displayedThreatType = threatType || inferredThreat.threatType
  const displayedPrimaryWarning = primaryWarning || inferredThreat.primaryWarning

  document.getElementById('blocked-url').textContent =
    blockedUrl || (host ? `Blocked host: ${host}` : 'Unknown URL')
  document.getElementById('score').textContent = `Status: ${status} - Safety score ${score}/100`
  document.getElementById('threat-name').textContent = `Threat name: ${displayedThreatName}`
  document.getElementById('threat-type').textContent = `Threat type: ${displayedThreatType}`
  document.getElementById('threat-reason').textContent = displayedPrimaryWarning
  updateDetailsLink({ url: blockedUrl, host, scanId: blockedScanId })
}

async function loadBlockedContext() {
  if (!blockedHost) {
    renderBlockedPage({
      url: blockedUrl,
      status: params.get('status') || 'Blocked',
      score: params.get('score') || '0',
      threatName: params.get('name') || undefined,
      threatType: params.get('threat') || undefined,
      primaryWarning: params.get('warning') || undefined,
      scanId: params.get('scan') || '',
    })
    return
  }

  const key = `blockedContext:${blockedHost}`
  const stored = await chrome.storage.local.get(key)
  const context = stored[key]

  if (context?.expiresAt && Date.now() <= context.expiresAt) {
    renderBlockedPage(context)
    return
  }

  const fallbackUrl = `https://${blockedHost}/`
  renderBlockedPage({
    url: fallbackUrl,
    host: blockedHost,
    status: params.get('status') || 'Blocked',
    score: params.get('score') || '0',
    threatName: params.get('name') || undefined,
    threatType: params.get('threat') || undefined,
    primaryWarning: params.get('warning') || undefined,
    scanId: params.get('scan') || '',
  })
}

document.getElementById('continue-button').addEventListener('click', () => {
  if (!blockedUrl && !blockedHost) return

  const continueButton = document.getElementById('continue-button')
  continueButton.disabled = true
  continueButton.textContent = 'Unblocking...'

  chrome.runtime.sendMessage(
    { type: 'unblock-site', url: blockedUrl, host: blockedHost },
    (response) => {
      if (chrome.runtime.lastError || response?.ok === false) {
        continueButton.disabled = false
        continueButton.textContent = 'Unblock and Continue'
        return
      }

      window.location.href = response?.url || blockedUrl || `https://${blockedHost}/`
    },
  )
})

document.getElementById('retry-history').addEventListener('click', () => {
  updateDetailsLink({ url: blockedUrl, host: blockedHost })
})

loadBlockedContext().catch((error) => {
  document.getElementById('history-status').textContent = 'History could not be synced: ' + error.message
  document.getElementById('retry-history').hidden = false
})
