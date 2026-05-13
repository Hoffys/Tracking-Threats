const params = new URLSearchParams(window.location.search)
const blockedHost = params.get('host') || ''
const APP_URL = 'http://localhost:5173/'

let blockedUrl = params.get('url') || ''

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

  if (/torrent|pirate|crack|cracked|keygen|warez|fitgirl|dodi|elamigos|gog-games|igg-games|igggames|oceanofgames|ovagames|steamrip|steamunlocked|online-fix|repack|repacks/.test(text)) {
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

function getDetailsUrl({ page = 'history', url = '', host = '' } = {}) {
  const detailsUrl = new URL(APP_URL)
  detailsUrl.searchParams.set('page', page)
  const target = url || host
  if (target) detailsUrl.searchParams.set('blocked', target)
  return detailsUrl.toString()
}

function renderBlockedPage({
  url = '',
  host = '',
  status = 'Blocked',
  score = '0',
  threatType = '',
  primaryWarning = '',
}) {
  blockedUrl = url
  const inferredThreat = inferThreatFromUrl(blockedUrl, host)
  const displayedThreatType = threatType || inferredThreat.threatType
  const displayedPrimaryWarning = primaryWarning || inferredThreat.primaryWarning

  document.getElementById('blocked-url').textContent =
    blockedUrl || (host ? `Blocked host: ${host}` : 'Unknown URL')
  document.getElementById('score').textContent = `Status: ${status} - Safety score ${score}/100`
  document.getElementById('threat-type').textContent = `Detected threat: ${displayedThreatType}`
  document.getElementById('threat-reason').textContent = displayedPrimaryWarning
  document.getElementById('details-link').href = getDetailsUrl({
    page: 'history',
    url: blockedUrl,
    host,
  })
}

async function loadBlockedContext() {
  if (!blockedHost) {
    renderBlockedPage({
      url: blockedUrl,
      status: params.get('status') || 'Blocked',
      score: params.get('score') || '0',
      threatType: params.get('threat') || undefined,
      primaryWarning: params.get('warning') || undefined,
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

  renderBlockedPage({
    host: blockedHost,
    status: params.get('status') || 'Blocked',
    score: params.get('score') || '0',
    threatType: params.get('threat') || undefined,
    primaryWarning: params.get('warning') || undefined,
  })
}

document.getElementById('continue-button').addEventListener('click', () => {
  if (!blockedUrl && !blockedHost) return

  chrome.runtime.sendMessage(
    { type: 'unblock-site', url: blockedUrl, host: blockedHost },
    () => {
      if (blockedUrl) {
        window.location.href = blockedUrl
      } else if (blockedHost) {
        window.location.href = `https://${blockedHost}/`
      }
    },
  )
})

loadBlockedContext()
