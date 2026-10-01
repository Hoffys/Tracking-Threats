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
      threatType: 'Piracy or illegal download risk',
      primaryWarning: 'This site matches piracy, cracked software, torrent, or repack indicators.',
    }
  }

  if (/casino|gambl(e|ing)|betting?|sportsbook|slots?|jackpot|poker|roulette|baccarat|sabong|freebet/.test(text)) {
    return {
      threatType: 'Gambling or betting risk',
      primaryWarning: 'This site matches gambling, betting, or cash-out indicators.',
    }
  }

  if (/secure|security|verify|verification|account|accounts|login|signin|password|billing|wallet|claim|reward|promo|bonus|update/.test(text)) {
    return {
      threatType: 'Phishing or credential theft risk',
      primaryWarning: 'This URL uses account, login, verification, or reward wording often used in phishing.',
    }
  }

  return {
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
  detailsLink.href = getDetailsUrl({ url, host, scanId })

  chrome.runtime.sendMessage({ type: 'get-linked-app-url' }, (response) => {
    if (chrome.runtime.lastError || !response?.ok || !response.appUrl) return
    detailsLink.href = getDetailsUrl({ appUrl: response.appUrl, url, host, scanId })
  })
}

function renderBlockedPage({
  url = '',
  host = '',
  status = 'Blocked',
  score = '0',
  threatType = '',
  primaryWarning = '',
  scanId = '',
}) {
  blockedUrl = url
  blockedScanId = scanId || blockedScanId
  const inferredThreat = inferThreatFromUrl(blockedUrl, host)
  const displayedThreatType = threatType || inferredThreat.threatType
  const displayedPrimaryWarning = primaryWarning || inferredThreat.primaryWarning

  document.getElementById('blocked-url').textContent =
    blockedUrl || (host ? `Blocked host: ${host}` : 'Unknown URL')
  document.getElementById('score').textContent = `Status: ${status} - Safety score ${score}/100`
  document.getElementById('threat-type').textContent = `Detected threat: ${displayedThreatType}`
  document.getElementById('threat-reason').textContent = displayedPrimaryWarning
  updateDetailsLink({ url: blockedUrl, host, scanId: blockedScanId })
}

async function loadBlockedContext() {
  if (!blockedHost) {
    renderBlockedPage({
      url: blockedUrl,
      status: params.get('status') || 'Blocked',
      score: params.get('score') || '0',
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
    chrome.runtime.sendMessage({ type: 'record-blocked-visit', url: context.url }, (response) => {
      if (response?.scan?.id) {
        blockedScanId = response.scan.id
        updateDetailsLink({ url: context.url, host: context.host, scanId: blockedScanId })
      }
    })
    return
  }

  const fallbackUrl = `https://${blockedHost}/`
  renderBlockedPage({
    url: fallbackUrl,
    host: blockedHost,
    status: params.get('status') || 'Blocked',
    score: params.get('score') || '0',
    threatType: params.get('threat') || undefined,
    primaryWarning: params.get('warning') || undefined,
    scanId: params.get('scan') || '',
  })
  chrome.runtime.sendMessage({ type: 'record-blocked-visit', url: fallbackUrl }, (response) => {
    if (response?.scan?.id) {
      blockedScanId = response.scan.id
      updateDetailsLink({ url: fallbackUrl, host: blockedHost, scanId: blockedScanId })
    }
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

const devicePairCodeInput = document.getElementById('devicePairCode')
const linkDeviceButton = document.getElementById('linkDeviceButton')
const devicePairStatus = document.getElementById('devicePairStatus')
const linkedDeviceInfo = document.getElementById('linkedDeviceInfo')
const devicePairForm = document.getElementById('devicePairForm')

async function loadLinkedDeviceInfo() {
  const stored = await chrome.storage.local.get([
    'linkedDeviceId',
    'linkedDeviceName',
    'linkedBrowserName',
  ])

  if (!stored.linkedDeviceId) {
    linkedDeviceInfo.style.display = 'none'
    devicePairForm.style.display = 'block'
    return
  }

  linkedDeviceInfo.style.display = 'block'
  linkedDeviceInfo.textContent =
    `Linked to: ${stored.linkedDeviceName || 'Device'} (${stored.linkedBrowserName || 'Browser'})`

  devicePairForm.style.display = 'none'
}

if (linkDeviceButton) {
  linkDeviceButton.addEventListener('click', async () => {
    const pairCode = String(devicePairCodeInput?.value ?? '')
      .trim()
      .toUpperCase()

    if (!/^[A-F0-9]{8}$/.test(pairCode)) {
      devicePairStatus.textContent =
        'Enter a valid 8-character device code.'
      return
    }

    linkDeviceButton.disabled = true
    devicePairStatus.textContent = 'Linking device...'

    try {
      const result = await chrome.runtime.sendMessage({
        type: 'PAIR_DEVICE',
        pairCode,
      })

      if (!result?.ok) {
        devicePairStatus.textContent =
          result?.error || 'Unable to link this browser.'
        return
      }

      devicePairStatus.textContent = 'Device linked successfully.'

      if (devicePairCodeInput) {
        devicePairCodeInput.value = ''
      }

      await loadLinkedDeviceInfo()
    } catch (error) {
      console.error('Pair device popup error:', error)

      devicePairStatus.textContent =
        'Unable to communicate with the extension.'
    } finally {
      linkDeviceButton.disabled = false
    }
  })
}

loadLinkedDeviceInfo()

loadBlockedContext()
