importScripts('config.js')

const API_BASE_URL = TRACKING_THREATS_CONFIG.API_BASE_URL.replace(/\/$/, '')
const API_URL = `${API_BASE_URL}/api/scan/url`
const EMAIL_API_URL = `${API_BASE_URL}/api/scan/email`
const FILE_API_URL = `${API_BASE_URL}/api/scan/file`
const SAFE_HOSTS_URL = `${API_BASE_URL}/api/safe-hosts`
const APP_URL = TRACKING_THREATS_CONFIG.APP_URL
const APP_ORIGIN = new URL(APP_URL).origin
const COOLDOWN_MS = 15000
const SAFE_HOST_SYNC_MS = 5000
const MAX_TRACKED = 200
const BLOCK_RULE_ID_BASE = 10000
const MAX_BLOCK_RULES = 250
const UNBLOCK_BYPASS_MS = 30000
const BLOCK_CONTEXT_TTL_MS = 5 * 60 * 1000
const CLIENT_ID_KEY = 'threattrackClientId'
const CLIENT_TOKEN_KEY = 'threattrackClientToken'
const EMAIL_CONSENT_KEY = 'trackingThreatsEmailConsent'
const EMAIL_CONSENT_VERSION = '2026.09'
const BYPASS_HOSTS_KEY = 'bypassHosts'
const ALLOWED_HOSTS_KEY = 'allowedHosts'
const NOTIFICATION_PREFIX = 'threattrack-scan:'
const PASS_THROUGH_HOSTS = new Set([
  'bing.com',
  'duckduckgo.com',
  'fbcdn.net',
  'fbsbx.com',
  'github.com',
  'google.com',
  'icloud.com',
  'mail.aol.com',
  'mail.com',
  'mail.google.com',
  'mail.proton.me',
  'mail.yahoo.com',
  'mail.zoho.com',
  'outlook.live.com',
  'outlook.office.com',
  'outlook.office365.com',
  'proton.me',
  'search.yahoo.com',
  'tracking-threats-production.up.railway.app',
])

const recentScans = new Map()
let blockedHosts = new Map()
const bypassHosts = new Map()
const notificationTargets = new Map()
const tabRedirectChains = new Map()
let clientToken = ''
let credentialPromise = null
let allowedHosts = new Set()
let safeHosts = new Set()

async function getClientCredentials(rejectedClientId = '') {
  if (credentialPromise) {
    const credential = await credentialPromise
    if (credential.clientId !== rejectedClientId) return credential
  }
  if (!credentialPromise) {
    credentialPromise = (async () => {
      const stored = await chrome.storage.local.get([CLIENT_ID_KEY, CLIENT_TOKEN_KEY])
      if (stored[CLIENT_ID_KEY] !== rejectedClientId &&
          /^cl_[a-f0-9]{32}$/.test(stored[CLIENT_ID_KEY] ?? '') &&
          /^[A-Za-z0-9_-]{40,80}$/.test(stored[CLIENT_TOKEN_KEY] ?? '')) {
        clientToken = stored[CLIENT_TOKEN_KEY]
        return { clientId: stored[CLIENT_ID_KEY], token: clientToken }
      }

      const response = await fetch(`${API_BASE_URL}/api/public/clients`, { method: 'POST' })
      if (!response.ok) throw new Error(await getScannerError(response, 'Client registration'))
      const credential = await response.json()
      if (!/^cl_[a-f0-9]{32}$/.test(credential.clientId ?? '') ||
          !/^[A-Za-z0-9_-]{40,80}$/.test(credential.token ?? '')) {
        throw new Error('Invalid client credential response')
      }
      clientToken = credential.token
      await chrome.storage.local.set({
        [CLIENT_ID_KEY]: credential.clientId,
        [CLIENT_TOKEN_KEY]: credential.token,
      })
      if (rejectedClientId) recentScans.clear()
      return credential
    })().finally(() => { credentialPromise = null })
  }
  return credentialPromise
}

async function getClientId() {
  return (await getClientCredentials()).clientId
}

async function detectBrowserName() {
  try {
    if (
      navigator.brave &&
      typeof navigator.brave.isBrave === 'function' &&
      await navigator.brave.isBrave()
    ) {
      return 'Brave'
    }
  } catch {
    // Ignore Brave detection errors
  }

  const userAgent = navigator.userAgent || ''

  if (userAgent.includes('Edg/')) {
    return 'Edge'
  }

  if (userAgent.includes('Chrome/')) {
    return 'Chrome'
  }

  return 'Other'
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== 'PAIR_DEVICE') {
    return
  }

  ;(async () => {
    try {
      const pairCode = String(message.pairCode ?? '')
        .trim()
        .toUpperCase()

      if (!/^[A-F0-9]{8}$/.test(pairCode)) {
        sendResponse({
          ok: false,
          error: 'Enter a valid 8-character device code.',
        })
        return
      }

      const browserName = await detectBrowserName()

      const response = await scanFetch(
        `${API_BASE_URL}/api/public/devices/pair`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            pairCode,
            browserName,
          }),
        },
      )

      const result = await response.json().catch(() => ({}))

      if (!response.ok) {
        sendResponse({
          ok: false,
          error: result.error || 'Unable to link this browser.',
        })
        return
      }

      await chrome.storage.local.set({
        linkedDeviceId: result.device?.deviceId ?? '',
        linkedDeviceName: result.device?.deviceName ?? '',
        linkedBrowserName: result.browserName ?? browserName,
      })

      sendResponse({
        ok: true,
        device: result.device,
        browserName: result.browserName ?? browserName,
      })
    } catch (error) {
      console.error('Device pairing failed:', error)

      sendResponse({
        ok: false,
        error: error?.message || 'Unable to link this browser.',
      })
    }
  })()

  return true
})

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== 'CREATE_DEVICE') {
    return
  }

  ;(async () => {
    try {
      const deviceName = String(message.deviceName ?? '').trim()

      if (!deviceName || deviceName.length > 80) {
        sendResponse({
          ok: false,
          error: 'Enter a valid device name.',
        })
        return
      }

      const browserName = await detectBrowserName()

      const response = await scanFetch(
        `${API_BASE_URL}/api/public/devices`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
          deviceName,
          browserName,
        }),
        },
      )

      const result = await response.json().catch(() => ({}))

      if (!response.ok) {
        sendResponse({
          ok: false,
          error: result.error || 'Unable to create device.',
        })
        return
      }

      await chrome.storage.local.set({
        linkedDeviceId: result.device?.deviceId ?? '',
        linkedDeviceName: result.device?.deviceName ?? deviceName,
        linkedBrowserName: browserName,
      })

      sendResponse({
        ok: true,
        device: result.device,
        browserName,
        pairCode: result.pairCode,
        expiresAt: result.expiresAt,
      })
    } catch (error) {
      console.error('Create device failed:', error)

      sendResponse({
        ok: false,
        error: error?.message || 'Unable to create device.',
      })
    }
  })()

  return true
})

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== 'GENERATE_PAIR_CODE') {
    return
  }

  ;(async () => {
    try {
      const response = await scanFetch(
        `${API_BASE_URL}/api/public/devices/pair-code`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({}),
        },
      )

      const result = await response.json().catch(() => ({}))

      if (!response.ok) {
        sendResponse({
          ok: false,
          error: result.error || 'Unable to generate pairing code.',
        })
        return
      }

      sendResponse({
        ok: true,
        pairCode: result.pairCode,
        expiresAt: result.expiresAt,
        deviceId: result.deviceId,
      })
    } catch (error) {
      console.error('Generate pairing code failed:', error)

      sendResponse({
        ok: false,
        error: error?.message || 'Unable to generate pairing code.',
      })
    }
  })()

  return true
})


async function scanFetch(url, options) {
  const send = (credential) => fetch(url, {
    ...options,
    body: options?.body
      ? JSON.stringify({ ...JSON.parse(options.body), clientId: credential.clientId })
      : undefined,
    headers: { ...options?.headers, 'X-Client-Token': credential.token },
  })
  const credential = await getClientCredentials()
  const response = await send(credential)
  if (!(await isRejectedCredential(response))) return response
  const replacement = await getClientCredentials(credential.clientId)
  return send(replacement)
}

async function isRejectedCredential(response) {
  if (response.status !== 403) return false
  const payload = await response.clone().json().catch(() => null)
  return payload?.code === 'CLIENT_ACCESS_DENIED' || payload?.error === 'Client access denied'
}

async function getVerifiedClientCredentials() {
  const credential = await getClientCredentials()
  const response = await fetch(`${API_BASE_URL}/api/public/clients/${credential.clientId}`, {
    headers: { 'X-Client-Token': credential.token },
    cache: 'no-store',
  })
  if (await isRejectedCredential(response)) return getClientCredentials(credential.clientId)
  if (!response.ok) throw new Error(await getScannerError(response, 'Client verification'))
  return credential
}

async function hasEmailScanConsent() {
  const stored = await chrome.storage.local.get(EMAIL_CONSENT_KEY)
  const consent = stored[EMAIL_CONSENT_KEY]
  return Boolean(consent?.accepted && consent?.noticeVersion === EMAIL_CONSENT_VERSION)
}

function getLinkedAppUrl(clientId, currentUrl = APP_URL) {
  const url = new URL(currentUrl)
  if (url.origin !== APP_ORIGIN) return getLinkedAppUrl(clientId)
  url.searchParams.set('client', clientId)
  return url.toString()
}

function getHistoryUrl(clientId, target = '') {
  const url = new URL(getLinkedAppUrl(clientId))
  url.searchParams.set('page', 'history')
  if (target) url.searchParams.set('blocked', target)
  return url.toString()
}

async function loadBlockedHosts() {
  const stored = await chrome.storage.local.get('blockedHosts')
  blockedHosts = new Map(stored.blockedHosts ?? [])
}

async function saveBlockedHosts() {
  await chrome.storage.local.set({
    blockedHosts: Array.from(blockedHosts.entries()),
  })
}

async function loadBypassHosts() {
  const stored = await chrome.storage.local.get(BYPASS_HOSTS_KEY)
  const now = Date.now()
  const activeEntries = (stored[BYPASS_HOSTS_KEY] ?? []).filter(
    ([, expiresAt]) => Number(expiresAt) > now,
  )
  bypassHosts.clear()
  activeEntries.forEach(([host, expiresAt]) => bypassHosts.set(host, expiresAt))
  if (activeEntries.length !== (stored[BYPASS_HOSTS_KEY] ?? []).length) {
    await saveBypassHosts()
  }
}

async function saveBypassHosts() {
  await chrome.storage.local.set({
    [BYPASS_HOSTS_KEY]: Array.from(bypassHosts.entries()),
  })
}

async function loadAllowedHosts() {
  allowedHosts = new Set()
  await chrome.storage.local.remove(ALLOWED_HOSTS_KEY)
}

async function saveAllowedHosts() {
  await chrome.storage.local.remove(ALLOWED_HOSTS_KEY)
}

function normalizeHost(host) {
  return host.replace(/^www\./, '')
}

function getHost(rawUrl) {
  try {
    return normalizeHost(new URL(rawUrl).hostname)
  } catch {
    return ''
  }
}

function isAppUrl(rawUrl) {
  try {
    return new URL(rawUrl).origin === APP_ORIGIN
  } catch {
    return false
  }
}

async function linkAppTab(tabId, rawUrl) {
  if (!tabId || tabId < 0 || !isAppUrl(rawUrl)) return false

  const url = new URL(rawUrl)
  const clientId = await getClientId()
  if (url.searchParams.get('client') === clientId) return false
  const linkedUrl = getLinkedAppUrl(clientId, url.toString())

  try {
    const updateResult = chrome.tabs.update(tabId, { url: linkedUrl })
    if (updateResult?.catch) updateResult.catch(() => {})
    return true
  } catch {
    return false
  }
}

function isPassThroughHost(host) {
  const normalizedHost = normalizeHost(host)
  return Array.from(PASS_THROUGH_HOSTS).some(
    (passThroughHost) =>
      normalizedHost === passThroughHost || normalizedHost.endsWith(`.${passThroughHost}`),
  )
}

function isMarkedSafeHost(host) {
  const normalizedHost = normalizeHost(host)
  return Array.from(safeHosts).some(
    (safeHost) => normalizedHost === safeHost || normalizedHost.endsWith(`.${safeHost}`),
  )
}

function isAllowedHost(host) {
  const normalizedHost = normalizeHost(host)
  return Array.from(allowedHosts).some(
    (allowedHost) => normalizedHost === allowedHost || normalizedHost.endsWith(`.${allowedHost}`),
  )
}

function getNextRuleId() {
  const usedIds = new Set(blockedHosts.values())
  for (let offset = 0; offset < MAX_BLOCK_RULES; offset += 1) {
    const candidate = BLOCK_RULE_ID_BASE + offset
    if (!usedIds.has(candidate)) return candidate
  }
  return null
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function getBlockContextKey(host) {
  return `blockedContext:${host}`
}

function getDetectedThreat(scan = {}) {
  const warningText = (scan.warningSigns ?? []).join(' ').toLowerCase()

  if (/piracy|torrent|cracked|keygen|warez|streaming|repack/.test(warningText)) {
    return 'Piracy or illegal download risk'
  }

  if (/gambling|betting|casino|cash-out|sportsbook/.test(warningText)) {
    return 'Gambling or betting risk'
  }

  if (/phishing|credential|password|login|account|verification|typosquatting|trusted brand/.test(warningText)) {
    return 'Phishing or credential theft risk'
  }

  if (/malware|abuse|malicious|harmful|urlhaus|virustotal/.test(warningText)) {
    return 'Malware or abuse reputation risk'
  }

  if (/private or reserved|no public|dns/.test(warningText)) {
    return 'Suspicious DNS or network risk'
  }

  return scan.status === 'Dangerous' ? 'Dangerous website risk' : 'Suspicious website risk'
}

function getPrimaryWarning(scan = {}) {
  return scan.warningSigns?.[0] ?? scan.summary ?? 'The scanner found dangerous URL indicators.'
}

async function saveBlockedContext(host, rawUrl, scan) {
  await chrome.storage.local.set({
    [getBlockContextKey(host)]: {
      host,
      url: rawUrl,
      scanId: scan?.id ?? '',
      status: scan?.status ?? 'Blocked',
      score: scan?.score ?? 0,
      threatType: getDetectedThreat(scan),
      primaryWarning: getPrimaryWarning(scan),
      expiresAt: Date.now() + BLOCK_CONTEXT_TTL_MS,
    },
  })
}

function getBlockRule(host, ruleId) {
  const escapedHost = escapeRegex(host)

  return {
    id: ruleId,
    priority: 1,
    // DNR redirects require destination-site host access. A block action works
    // with declarativeNetRequest alone; the tab API opens our warning separately.
    action: { type: 'block' },
    condition: {
      regexFilter: `^https?://([^/?#]+\\.)?${escapedHost}([/?#].*)?$`,
      resourceTypes: ['main_frame'],
    },
  }
}

async function syncBlockRules() {
  const entries = Array.from(blockedHosts.entries())
  const ruleIds = entries.map(([, ruleId]) => ruleId)

  if (ruleIds.length === 0) return

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: ruleIds,
    addRules: entries.map(([host, ruleId]) => getBlockRule(host, ruleId)),
  })
}

async function clearPassThroughBlockRules() {
  const entries = Array.from(blockedHosts.entries()).filter(([host]) =>
    isPassThroughHost(host),
  )
  if (entries.length === 0) return

  const removeRuleIds = entries.map(([, ruleId]) => ruleId)
  for (const [host] of entries) blockedHosts.delete(host)

  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds })
  await saveBlockedHosts()
}

async function syncSafeHosts() {
  try {
    const response = await fetch(SAFE_HOSTS_URL)
    if (!response.ok) throw new Error(`Safe host sync returned ${response.status}`)
    const payload = await response.json()
    safeHosts = new Set((payload.hosts ?? []).map(normalizeHost).filter(Boolean))

    const entriesToRemove = Array.from(blockedHosts.entries()).filter(([host]) =>
      isMarkedSafeHost(host),
    )
    if (entriesToRemove.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: entriesToRemove.map(([, ruleId]) => ruleId),
      })
      for (const [host] of entriesToRemove) {
        blockedHosts.delete(host)
        bypassHosts.set(host, Date.now() + UNBLOCK_BYPASS_MS)
        await chrome.storage.local.remove(getBlockContextKey(host))
      }
      await saveBlockedHosts()
    }

    return true
  } catch (error) {
    await saveStatus({
      ok: false,
      lastUrl: 'Safe host sync',
      error: error.message,
    })
    return false
  }
}

function isTrackableUrl(rawUrl) {
  try {
    const url = new URL(rawUrl)
    if (!['http:', 'https:'].includes(url.protocol)) return false
    if (['localhost', '127.0.0.1'].includes(url.hostname)) return false
    if (isPassThroughHost(url.hostname)) return false
    return true
  } catch {
    return false
  }
}

function remember(url, scan = null) {
  recentScans.set(url, { scan, timestamp: Date.now() })
  if (recentScans.size > MAX_TRACKED) {
    const oldest = recentScans.keys().next().value
    recentScans.delete(oldest)
  }
}

function getRecentScan(url) {
  const previous = recentScans.get(url)
  if (!previous) return null
  if (Date.now() - previous.timestamp >= COOLDOWN_MS) {
    recentScans.delete(url)
    return null
  }
  return previous.scan
}

function isBlockedScan(scan) {
  return scan?.status === 'Dangerous' || scan?.blocked || scan?.responseStatus === 'Blocked'
}

function getDownloadFileName(downloadItem = {}) {
  const rawName = downloadItem.filename || downloadItem.finalUrl || downloadItem.url || ''
  const fromPath = rawName.split(/[\\/]/).pop()
  if (fromPath && fromPath !== rawName) return fromPath

  try {
    const pathName = new URL(rawName).pathname.split('/').filter(Boolean).pop()
    return pathName || 'Downloaded file'
  } catch {
    return rawName || 'Downloaded file'
  }
}

function hasBypass(host) {
  const expiresAt = bypassHosts.get(host)
  if (!expiresAt) return false
  if (Date.now() > expiresAt) {
    bypassHosts.delete(host)
    saveBypassHosts().catch(() => {})
    return false
  }
  return true
}

async function rememberBlockedSite(rawUrl, scan = null) {
  const host = getHost(rawUrl)
  if (!host) return
  if (isMarkedSafeHost(host)) return
  if (isAllowedHost(host)) return
  if (hasBypass(host)) return

  await saveBlockedContext(host, rawUrl, scan)

  let ruleId = blockedHosts.get(host)
  if (!ruleId) {
    ruleId = getNextRuleId()
    if (!ruleId) return
    blockedHosts.set(host, ruleId)
    await saveBlockedHosts()
  }

  const existingRules = await chrome.declarativeNetRequest.getDynamicRules()
  const hasRule = existingRules.some((rule) => rule.id === ruleId)
  if (hasRule) return

  await chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [getBlockRule(host, ruleId)],
    removeRuleIds: [],
  })
}

async function unblockSite({ rawUrl, host: fallbackHost }) {
  const host = getHost(rawUrl) || fallbackHost?.replace(/^www\./, '')
  if (!host) return false

  bypassHosts.set(host, Date.now() + UNBLOCK_BYPASS_MS)
  const matchingBlockedHosts = Array.from(blockedHosts.keys()).filter(
    (blockedHost) =>
      blockedHost === host ||
      host.endsWith(`.${blockedHost}`) ||
      blockedHost.endsWith(`.${host}`),
  )
  matchingBlockedHosts.forEach((blockedHost) =>
    bypassHosts.set(blockedHost, Date.now() + UNBLOCK_BYPASS_MS),
  )
  await saveBypassHosts()
  recentScans.delete(rawUrl)
  recentScans.delete(`blocked-visit:${rawUrl}`)
  await chrome.storage.local.remove(getBlockContextKey(host))
  await Promise.all(matchingBlockedHosts.map((blockedHost) =>
    chrome.storage.local.remove(getBlockContextKey(blockedHost)),
  ))

  const hostParts = host.split('.')
  const hostCandidates = hostParts
    .map((_, index) => hostParts.slice(index).join('.'))
    .filter((candidate) => candidate.includes('.'))
  const escapedHosts = hostCandidates.map(escapeRegex)
  const ruleIds = new Set()
  matchingBlockedHosts.forEach((blockedHost) => {
    const ruleId = blockedHosts.get(blockedHost)
    if (ruleId) ruleIds.add(ruleId)
  })

  const existingRules = await chrome.declarativeNetRequest.getDynamicRules()
  existingRules.forEach((rule) => {
    if (escapedHosts.some((escapedHost) => rule.condition?.regexFilter?.includes(escapedHost))) {
      ruleIds.add(rule.id)
    }
  })

  matchingBlockedHosts.forEach((blockedHost) => blockedHosts.delete(blockedHost))

  if (ruleIds.size > 0) {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: Array.from(ruleIds),
    })
  }
  await saveBlockedHosts()
  return {
    ok: true,
    url: rawUrl || `https://${host}/`,
  }
}

async function saveStatus(status) {
  const clientId = await getClientId()
  await chrome.storage.local.set({
    threattrackStatus: {
      ...status,
      clientId,
      updatedAt: new Date().toISOString(),
      appUrl: getLinkedAppUrl(clientId),
    },
  })
  await updateBadge(status)
}

async function updateBadge(status) {
  if (!chrome.action) return
  const incomplete = status.coverage?.status !== 'complete'
  const text = !status.ok ? 'OFF' : ['Dangerous', 'Blocked'].includes(status.lastStatus) ? '!'
    : status.lastStatus === 'Suspicious' ? '?' : incomplete ? '?' : 'OK'
  const color = !status.ok ? '#64748b' : text === '!' ? '#be123c' : text === '?' ? '#b45309' : '#0f766e'
  await Promise.all([
    chrome.action.setBadgeText({ text }),
    chrome.action.setBadgeBackgroundColor({ color }),
  ]).catch(() => { /* Badge availability must not interrupt protection. */ })
}

async function getScannerError(response, label = 'Scanner') {
  if (response.status === 429) {
    return `${label} busy: too many scan requests. Please wait a moment.`
  }

  try {
    const payload = await response.clone().json()
    if (payload?.error) return `${label}: ${payload.error}`
  } catch {
    // Non-JSON responses still get a useful status message below.
  }

  return `${label} returned ${response.status}`
}

function getScanNotification(scan, rawUrl) {
  const score = Number(scan?.score ?? 0)
  const status = scan?.status === 'Dangerous' || scan?.blocked ? 'Blocked' : scan?.status
  const host = getHost(rawUrl) || rawUrl
  const piracyCaution = status === 'Safe' && scan?.categories?.includes('piracy-content')
  const contentCaution = status === 'Safe' && scan?.categories?.some((category) => typeof category === 'string' && category.endsWith('-content'))

  if (status === 'Blocked') {
    return {
      title: 'Tracking Threats risk detected',
      message: `${host} has risk indicators. Rule-based score ${score}/100; not a probability.`,
    }
  }

  if (status === 'Suspicious') {
    return {
      title: 'Tracking Threats caution',
      message: `${host} has warning signs. Rule-based score ${score}/100; not a probability.`,
    }
  }

  if (piracyCaution) {
    return {
      title: 'Tracking Threats: download risk unknown',
      message: `${host}: no strong phishing indicators were found, but piracy-related sources may expose you to malware, fake mirrors, tampered files, and copyright risk.`,
    }
  }

  if (contentCaution) {
    return {
      title: 'Tracking Threats: content warning',
      message: `${host}: no strong phishing indicators were found, but a separate content-risk category needs review before continuing.`,
    }
  }

  return {
    title: 'Tracking Threats: appears safe',
    message: `${host}: appears safe based on this scan. ${scan?.coverage?.status === 'complete' ? 'Configured reputation checks responded.' : 'Verification was limited.'} Scan finished. Score ${score}/100; not a safety guarantee.`,
  }
}

async function notifyScanResult(rawUrl, scan) {
  if (!rawUrl || !scan || scan.ok === false) return

  try {
    const clientId = await getClientId()
    const notificationId = `${NOTIFICATION_PREFIX}${scan.id ?? Date.now()}`
    const notification = getScanNotification(scan, rawUrl)
    const historyUrl = new URL(getHistoryUrl(clientId, rawUrl))
    if (scan.id) historyUrl.searchParams.set('scan', scan.id)
    notificationTargets.set(notificationId, historyUrl.toString())

    await chrome.notifications.create(notificationId, {
      type: 'basic',
      iconUrl: 'icons/icon-128.png',
      title: notification.title,
      message: notification.message,
      priority: scan.status === 'Dangerous' || scan.blocked ? 2 : 0,
    })
  } catch {
    // Browser or OS notification settings should not stop scanning or blocking.
  }
}

function openBlockedPage(tabId, rawUrl, scan) {
  if (!tabId || tabId < 0) return

  const blockedUrl = chrome.runtime.getURL(
    `blocked.html?url=${encodeURIComponent(rawUrl)}&score=${encodeURIComponent(
      scan.score,
    )}&status=${encodeURIComponent(scan.status)}&threat=${encodeURIComponent(
      getDetectedThreat(scan),
    )}&warning=${encodeURIComponent(getPrimaryWarning(scan))}&scan=${encodeURIComponent(
      scan.id ?? '',
    )}`,
  )

  try {
    const updateResult = chrome.tabs.update(tabId, { url: blockedUrl })
    if (updateResult?.catch) {
      updateResult.catch(() => {
        // Tab may close or become unavailable before the redirect finishes.
      })
    }
  } catch {
    // Tab may close or become unavailable before the redirect finishes.
  }
}

async function scanUrl(rawUrl, reason = 'navigation', tabId = null) {
  if (!isTrackableUrl(rawUrl)) return null
  await syncSafeHosts()
  const host = getHost(rawUrl)
  if (isAllowedHost(host)) {
    await unblockSite({ rawUrl, host })
    return { status: 'Allowed', score: 100, blocked: false, coverage: { status: 'local-only', checkedProviders: 0, totalProviders: 0, limitations: ['Allowed by a local exception; reputation checks were not run.'] }, categories: [] }
  }
  if (isMarkedSafeHost(host)) {
    const safeScan = {
      type: 'URL',
      target: rawUrl,
      score: 100,
      status: 'Safe',
      coverage: { status: 'local-only', checkedProviders: 0, totalProviders: 0, limitations: ['Allowed by a local exception; reputation checks were not run.'] }, categories: [],
      action: 'Allowed',
      blocked: false,
      warningSigns: [],
      recommendations: ['This site was marked safe in Tracking Threats.'],
    }
    remember(rawUrl, safeScan)
    await unblockSite({ rawUrl, host })
    await saveStatus({
      ok: true,
      lastUrl: rawUrl,
      lastStatus: 'Safe',
      lastScore: 100,
    })
    return safeScan
  }
  const previewOnly = reason === 'google-search-result'
  const bypassActive = hasBypass(getHost(rawUrl))

  const recentScan = previewOnly ? null : getRecentScan(rawUrl)
  if (recentScan) {
    if (isBlockedScan(recentScan) && !bypassActive) {
      await rememberBlockedSite(rawUrl, recentScan)
      openBlockedPage(tabId, rawUrl, recentScan)
    }
    return recentScan
  }

  if (!previewOnly) remember(rawUrl)
  try {
    const clientId = await getClientId()
    const response = await scanFetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: rawUrl,
        source: 'browser-extension',
        reason,
        preview: previewOnly,
        clientId,
      }),
    })

    if (!response.ok) throw new Error(await getScannerError(response))
    const scan = await response.json()
    if (!previewOnly) remember(rawUrl, scan)
    await saveStatus({
      ok: true,
      lastUrl: rawUrl,
      lastStatus: scan.status,
      lastScore: scan.score,
      coverage: scan.coverage,
      categories: scan.categories,
    })
    if (!previewOnly) {
      await notifyScanResult(rawUrl, scan)
    }

    if (!previewOnly && isBlockedScan(scan) && !bypassActive) {
      await rememberBlockedSite(rawUrl, scan)
      openBlockedPage(tabId, rawUrl, scan)
    }

    return scan
  } catch (error) {
    await saveStatus({
      ok: false,
      lastUrl: rawUrl,
      error: error.message,
    })
    return { ok: false, error: error.message }
  }
}

async function previewUrl(rawUrl, reason = 'search-result-preview') {
  if (!isTrackableUrl(rawUrl)) return null
  await syncSafeHosts()
  const host = getHost(rawUrl)
  if (isAllowedHost(host) || isMarkedSafeHost(host)) {
    return {
      type: 'URL',
      target: rawUrl,
      score: 100,
      status: 'Safe',
      coverage: { status: 'local-only', checkedProviders: 0, totalProviders: 0, limitations: ['Allowed by a local exception; reputation checks were not run.'] }, categories: [],
      action: 'Allowed',
      blocked: false,
      warningSigns: [],
      recommendations: ['This site is currently allowed in Tracking Threats.'],
    }
  }

  const response = await scanFetch(API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url: rawUrl,
      source: 'browser-search-preview',
      reason,
      preview: true,
    }),
  })

  if (!response.ok) throw new Error(await getScannerError(response))
  return response.json()
}

async function recordBlockedVisit(rawUrl) {
  if (!isTrackableUrl(rawUrl)) return null
  await syncSafeHosts()
  const host = getHost(rawUrl)
  if (isAllowedHost(host)) {
    await unblockSite({ rawUrl, host })
    return { status: 'Allowed', score: 100, blocked: false, coverage: { status: 'local-only', checkedProviders: 0, totalProviders: 0, limitations: ['Allowed by a local exception; reputation checks were not run.'] }, categories: [] }
  }
  if (hasBypass(host)) return { status: 'Allowed', score: 100, blocked: false, coverage: { status: 'local-only', checkedProviders: 0, totalProviders: 0, limitations: ['Allowed by a local exception; reputation checks were not run.'] }, categories: [] }
  if (isMarkedSafeHost(host)) {
    await unblockSite({ rawUrl, host })
    return { status: 'Safe', score: 100, blocked: false, coverage: { status: 'local-only', checkedProviders: 0, totalProviders: 0, limitations: ['Allowed by a local exception; reputation checks were not run.'] }, categories: [] }
  }

  const cooldownKey = `blocked-visit:${rawUrl}`
  if (getRecentScan(cooldownKey)) return null
  remember(cooldownKey, { status: 'recording' })

  try {
    const clientId = await getClientId()
    const response = await scanFetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: rawUrl,
        source: 'browser-extension',
        reason: 'blocked-rule-hit',
        clientId,
      }),
    })

    if (!response.ok) throw new Error(await getScannerError(response))
    const scan = await response.json()
    remember(rawUrl, scan)
    if (!hasBypass(host)) {
      await rememberBlockedSite(rawUrl, scan)
    }
    await saveStatus({
      ok: true,
      lastUrl: rawUrl,
      lastStatus: scan.status,
      lastScore: scan.score,
      coverage: scan.coverage,
      categories: scan.categories,
    })
    await notifyScanResult(rawUrl, scan)
    return scan
  } catch (error) {
    await saveStatus({
      ok: false,
      lastUrl: rawUrl,
      error: error.message,
    })
    return { ok: false, error: error.message }
  }
}

async function scanEmailContent({ sender = '', subject = '', body = '' }) {
  try {
    if (!(await hasEmailScanConsent())) {
      throw new Error('Email scanning requires explicit user consent')
    }
    const clientId = await getClientId()
    const response = await scanFetch(EMAIL_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sender,
        subject,
        body,
        source: 'browser-email-monitor',
        clientId,
        privacyAccepted: true,
        privacyNoticeVersion: EMAIL_CONSENT_VERSION,
      }),
    })

    if (!response.ok) throw new Error(await getScannerError(response, 'Email scanner'))
    const scan = await response.json()
    await saveStatus({
      ok: true,
      lastUrl: 'Email scan',
      lastStatus: scan.status,
      lastScore: scan.score,
      coverage: scan.coverage,
      categories: scan.categories,
    })
    return scan
  } catch (error) {
    await saveStatus({
      ok: false,
      lastUrl: 'Email scan',
      error: error.message,
    })
    return { ok: false, error: error.message }
  }
}

async function scanDownloadFile(downloadItem, clientId) {
  const response = await scanFetch(FILE_API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fileName: getDownloadFileName(downloadItem),
      mimeType: downloadItem.mime || '',
      size: Number(downloadItem.totalBytes || downloadItem.fileSize || 0),
      content: '',
      source: 'browser-download-monitor',
      clientId,
    }),
  })

  if (!response.ok) throw new Error(await getScannerError(response, 'File scanner'))
  return response.json()
}

async function scanDownloadUrl(downloadItem, clientId) {
  if (!isTrackableUrl(downloadItem.url)) return null

  const response = await scanFetch(API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url: downloadItem.url,
      source: 'browser-download-url',
      reason: 'download-url-check',
      clientId,
    }),
  })

  if (!response.ok) throw new Error(await getScannerError(response))
  const scan = await response.json()
  if (isBlockedScan(scan)) await rememberBlockedSite(downloadItem.url, scan)
  return scan
}

async function cancelDangerousDownload(downloadItem, scan) {
  let cancelled = false
  try {
    await chrome.downloads.cancel(downloadItem.id)
    cancelled = true
  } catch {
    // The download may already be complete or unavailable.
  }

  await saveStatus({
    ok: true,
    lastUrl: getDownloadFileName(downloadItem),
    lastStatus: cancelled ? 'Blocked' : 'Dangerous',
    lastScore: scan?.score ?? 0,
    coverage: scan?.coverage,
    categories: scan?.categories,
    ...(cancelled ? {} : { downloadWarning: 'Risk detected, but the browser could not cancel this download. It may already be complete.' }),
  })
  await notifyScanResult(downloadItem.url || getDownloadFileName(downloadItem), {
    ...scan,
    status: 'Dangerous',
    blocked: cancelled,
  })
  return cancelled
}

async function scanDownload(downloadItem) {
  if (!downloadItem?.id) return null
  let paused = false
  let blocked = false
  try {
    try { await chrome.downloads.pause(downloadItem.id); paused = true } catch { /* Browser may refuse to pause a completed download. */ }
    const clientId = await getClientId()
    const urlScan = await scanDownloadUrl(downloadItem, clientId)
    if (isBlockedScan(urlScan)) {
      blocked = await cancelDangerousDownload(downloadItem, urlScan)
      return urlScan
    }

    const fileScan = await scanDownloadFile(downloadItem, clientId)
    if (isBlockedScan(fileScan)) {
      blocked = await cancelDangerousDownload(downloadItem, fileScan)
      return fileScan
    }

    await saveStatus({
      ok: true,
      lastUrl: getDownloadFileName(downloadItem),
      lastStatus: fileScan.status,
      lastScore: fileScan.score,
      coverage: fileScan.coverage,
      categories: fileScan.categories,
    })
    return fileScan
  } catch (error) {
    await saveStatus({
      ok: false,
      lastUrl: getDownloadFileName(downloadItem),
      error: error.message,
    })
    return { ok: false, error: error.message }
  } finally {
    if (paused && !blocked) {
      try { await chrome.downloads.resume(downloadItem.id) } catch { /* Download may have been removed. */ }
    }
  }
}

async function handleTabUrl(tabId, url, reason) {
  if (await linkAppTab(tabId, url)) return
  scanUrl(url, reason, tabId)
}

function collectRenderedPageSignals() {
  const limited = (value, max = 100) => Math.min(max, Math.max(0, Number(value) || 0))
  const pageUrl = new URL(location.href)
  const forms = [...document.forms].slice(0, 100)
  const passwordFields = limited(document.querySelectorAll('input[type="password"]').length)
  let externalFormActions = 0
  for (const form of forms) {
    try {
      const target = new URL(form.action || location.href, location.href)
      if (target.hostname !== pageUrl.hostname) externalFormActions += 1
    } catch { externalFormActions += 1 }
  }
  const candidates = [...document.querySelectorAll('form,iframe')].slice(0, 100)
  const hiddenFrames = limited(candidates.filter((element) => {
    const style = getComputedStyle(element)
    return style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) === 0
  }).length)
  const text = `${document.title} ${(document.body?.innerText ?? '').slice(0, 20000)}`
  const scripts = [...document.scripts].slice(0, 100).map((script) => script.textContent ?? '').join('\n').slice(0, 100000)
  return {
    title: document.title.slice(0, 200),
    passwordFields,
    formCount: limited(forms.length),
    externalFormActions: limited(externalFormActions),
    hiddenFrames,
    credentialLanguage: /\b(sign[ -]?in|log[ -]?in|verify|password|passcode|one[ -]?time|otp|credit card|bank account)\b/i.test(text),
    obfuscatedScripts: /(?:eval\s*\(|atob\s*\(|fromCharCode\s*\(|document\.write\s*\()/i.test(scripts),
  }
}

async function inspectActivePage() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  if (!tab?.id || !isTrackableUrl(tab.url)) throw new Error('Open a normal HTTP or HTTPS page to inspect it')
  const injected = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: collectRenderedPageSignals })
  const snapshot = injected?.[0]?.result
  if (!snapshot) throw new Error('The page did not return inspection details')
  snapshot.redirectChain = tabRedirectChains.get(tab.id) ?? [tab.url]
  const response = await scanFetch(API_URL, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: tab.url, source: 'browser-extension', reason: 'rendered-page-inspection', pageSnapshot: snapshot }),
  })
  if (!response.ok) throw new Error(await getScannerError(response))
  const scan = await response.json()
  remember(tab.url, scan)
  await saveStatus({ ok: true, lastUrl: tab.url, lastStatus: scan.status, lastScore: scan.score,
    coverage: scan.coverage, categories: scan.categories })
  await notifyScanResult(tab.url, scan)
  if (isBlockedScan(scan) && !hasBypass(getHost(tab.url))) {
    await rememberBlockedSite(tab.url, scan)
    openBlockedPage(tab.id, tab.url, scan)
  }
  return scan
}

if (chrome.downloads?.onCreated) {
  chrome.downloads.onCreated.addListener((downloadItem) => {
    scanDownload(downloadItem)
  })
}

chrome.tabs.onUpdated.addListener((_tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    handleTabUrl(tab.id, tab.url, 'tab-complete')
  }
})

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId)
    if (tab.url) handleTabUrl(tab.id, tab.url, 'tab-activated')
  } catch {
    // Tab may disappear before Chrome returns it.
  }
})

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    const prior = tabRedirectChains.get(details.tabId) ?? []
    const redirected = details.transitionQualifiers?.some((item) => item === 'server_redirect' || item === 'client_redirect')
    tabRedirectChains.set(details.tabId, redirected ? [...prior, details.url].slice(-5) : [details.url])
    handleTabUrl(details.tabId, details.url, details.transitionType ?? 'navigation')
  }
})

chrome.tabs.onRemoved.addListener((tabId) => tabRedirectChains.delete(tabId))

chrome.webNavigation.onErrorOccurred?.addListener(async (details) => {
  const host = getHost(details.url)
  if (details.frameId !== 0 || !details.error?.includes('ERR_BLOCKED_BY_CLIENT') || !blockedHosts.has(host) || hasBypass(host)) return
  const key = getBlockContextKey(host)
  const stored = await chrome.storage.local.get(key)
  const context = stored[key]
  openBlockedPage(details.tabId, details.url, {
    status: context?.status ?? 'Dangerous', score: context?.score ?? 0,
    id: context?.scanId, warningSigns: context?.primaryWarning ? [context.primaryWarning] : [],
  })
})

// History API navigations do not necessarily produce an onCommitted event.
chrome.webNavigation.onHistoryStateUpdated?.addListener((details) => {
  if (details.frameId === 0) handleTabUrl(details.tabId, details.url, 'history-state')
})

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'scan-candidate-url' && message.url) {
    scanUrl(message.url, message.reason ?? 'content-script')
      .then((scan) => sendResponse({ ok: true, scan }))
      .catch((error) => sendResponse({ ok: false, error: error.message }))
    return true
  }

  if (message?.type === 'inspect-active-page') {
    inspectActivePage()
      .then((scan) => sendResponse({ ok: true, scan }))
      .catch((error) => sendResponse({ ok: false, error: error.message }))
    return true
  }

  if (message?.type === 'preview-candidate-url' && message.url) {
    previewUrl(message.url, message.reason ?? 'search-result-preview')
      .then((scan) => sendResponse({ ok: true, scan }))
      .catch((error) => sendResponse({ ok: false, error: error.message }))
    return true
  }

  if (message?.type === 'scan-email-content') {
    scanEmailContent(message.email ?? {})
      .then((scan) => sendResponse({ ok: true, scan }))
      .catch((error) => sendResponse({ ok: false, error: error.message }))
    return true
  }

  if (message?.type === 'unblock-site' && (message.url || message.host)) {
    unblockSite({ rawUrl: message.url, host: message.host })
      .then((result) => sendResponse(result))
      .catch((error) => sendResponse({ ok: false, error: error.message }))
    return true
  }

  if (message?.type === 'record-blocked-visit' && message.url) {
    recordBlockedVisit(message.url)
      .then((scan) => sendResponse({ ok: true, scan }))
      .catch((error) => sendResponse({ ok: false, error: error.message }))
    return true
  }

  if (message?.type === 'get-linked-app-url') {
    getClientId()
      .then((clientId) => sendResponse({ ok: true, clientId, appUrl: getLinkedAppUrl(clientId) }))
      .catch((error) => sendResponse({ ok: false, error: error.message }))
    return true
  }

  if (message?.type === 'get-client-credential') {
    try {
      if (new URL(_sender.url).origin !== APP_ORIGIN) {
        sendResponse({ ok: false, error: 'Untrusted page' })
        return false
      }
    } catch {
      sendResponse({ ok: false, error: 'Untrusted page' })
      return false
    }
    getVerifiedClientCredentials()
      .then((credential) => sendResponse({ ok: true, ...credential }))
      .catch((error) => sendResponse({ ok: false, error: error.message }))
    return true
  }

  return false
})

chrome.notifications.onClicked.addListener((notificationId) => {
  const targetUrl = notificationTargets.get(notificationId)
  if (!targetUrl) return
  chrome.tabs.create({ url: targetUrl })
  chrome.notifications.clear(notificationId)
})

Promise.all([loadBlockedHosts(), loadBypassHosts(), loadAllowedHosts()])
  .then(syncSafeHosts)
  .then(clearPassThroughBlockRules)
  .then(syncBlockRules)
  .catch(() => {
    // Storage may be temporarily unavailable during extension startup.
  })

// MV3 workers suspend: alarms wake the worker, ordinary intervals do not.
chrome.alarms.create('tracking-threats-safe-hosts', { periodInMinutes: Math.max(1, SAFE_HOST_SYNC_MS / 60000) })
chrome.storage.local.get('threattrackStatus').then(({ threattrackStatus }) => {
  if (threattrackStatus) return updateBadge(threattrackStatus)
}).catch(() => {})

async function reportExtensionUsage() {
  try {
    await scanFetch(`${API_BASE_URL}/api/public/extension/heartbeat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        version: chrome.runtime.getManifest().version,
        browserName: await detectBrowserName(),
      }),
    })
  } catch {
    // Retry on the next alarm; reporting must not interrupt scans.
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'tracking-threats-usage') reportExtensionUsage()
  if (alarm.name === 'tracking-threats-safe-hosts') syncSafeHosts().catch(() => {})
})
chrome.alarms.create('tracking-threats-usage', { periodInMinutes: 5 })
reportExtensionUsage()
