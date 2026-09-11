importScripts('config.js')

const API_BASE_URL = TRACKING_THREATS_CONFIG.API_BASE_URL.replace(/\/$/, '')
const API_URL = `${API_BASE_URL}/api/scan/url`
const EMAIL_API_URL = `${API_BASE_URL}/api/scan/email`
const SAFE_HOSTS_URL = `${API_BASE_URL}/api/safe-hosts`
const APP_URL = TRACKING_THREATS_CONFIG.APP_URL
const COOLDOWN_MS = 15000
const SAFE_HOST_SYNC_MS = 5000
const MAX_TRACKED = 200
const BLOCK_RULE_ID_BASE = 10000
const MAX_BLOCK_RULES = 250
const UNBLOCK_BYPASS_MS = 30000
const BLOCK_CONTEXT_TTL_MS = 5 * 60 * 1000
const CLIENT_ID_KEY = 'threattrackClientId'
const BYPASS_HOSTS_KEY = 'bypassHosts'
const ALLOWED_HOSTS_KEY = 'allowedHosts'
const NOTIFICATION_PREFIX = 'threattrack-scan:'
const PASS_THROUGH_HOSTS = new Set([
  'bing.com',
  'duckduckgo.com',
  'github.com',
  'google.com',
  'search.yahoo.com',
  'tracking-threats-production.up.railway.app',
])

const recentScans = new Map()
let blockedHosts = new Map()
const bypassHosts = new Map()
const notificationTargets = new Map()
let allowedHosts = new Set()
let safeHosts = new Set()

async function getClientId() {
  const stored = await chrome.storage.local.get(CLIENT_ID_KEY)
  if (stored[CLIENT_ID_KEY]) return stored[CLIENT_ID_KEY]

  const clientId = crypto.randomUUID()
  await chrome.storage.local.set({ [CLIENT_ID_KEY]: clientId })
  return clientId
}

function getLinkedAppUrl(clientId) {
  const url = new URL(APP_URL)
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
  const stored = await chrome.storage.local.get(ALLOWED_HOSTS_KEY)
  allowedHosts = new Set((stored[ALLOWED_HOSTS_KEY] ?? []).map(normalizeHost).filter(Boolean))
}

async function saveAllowedHosts() {
  await chrome.storage.local.set({
    [ALLOWED_HOSTS_KEY]: Array.from(allowedHosts),
  })
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

function isPassThroughHost(host) {
  return PASS_THROUGH_HOSTS.has(normalizeHost(host))
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
    action: {
      type: 'redirect',
      redirect: {
        regexSubstitution: `${chrome.runtime.getURL('blocked.html')}?host=${encodeURIComponent(
          host,
        )}`,
      },
    },
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

  allowedHosts.add(host)
  await saveAllowedHosts()
  bypassHosts.set(host, Date.now() + UNBLOCK_BYPASS_MS)
  await saveBypassHosts()
  recentScans.delete(rawUrl)
  recentScans.delete(`blocked-visit:${rawUrl}`)
  await chrome.storage.local.remove(getBlockContextKey(host))

  const escapedHost = escapeRegex(host)
  const ruleIds = new Set()
  const ruleId = blockedHosts.get(host)
  if (ruleId) ruleIds.add(ruleId)

  const existingRules = await chrome.declarativeNetRequest.getDynamicRules()
  existingRules.forEach((rule) => {
    if (rule.condition?.regexFilter?.includes(escapedHost)) {
      ruleIds.add(rule.id)
    }
  })

  Array.from(blockedHosts.keys()).forEach((blockedHost) => {
    if (blockedHost === host || blockedHost.endsWith(`.${host}`)) {
      blockedHosts.delete(blockedHost)
    }
  })

  if (ruleIds.size > 0) {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: Array.from(ruleIds),
    })
  }
  await saveBlockedHosts()
  return true
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
}

function getScanNotification(scan, rawUrl) {
  const score = Number(scan?.score ?? 0)
  const status = scan?.status === 'Dangerous' || scan?.blocked ? 'Blocked' : scan?.status
  const host = getHost(rawUrl) || rawUrl

  if (status === 'Blocked') {
    return {
      title: 'Tracking Threats blocked a risky site',
      message: `${host} was marked Dangerous. Safety score ${score}/100.`,
    }
  }

  if (status === 'Suspicious') {
    return {
      title: 'Tracking Threats caution',
      message: `${host} has warning signs. Safety score ${score}/100.`,
    }
  }

  return {
    title: 'Tracking Threats scan complete',
    message: `${host} looks safe. Safety score ${score}/100.`,
  }
}

async function notifyScanResult(rawUrl, scan) {
  if (!rawUrl || !scan || scan.ok === false) return

  try {
    const clientId = await getClientId()
    const notificationId = `${NOTIFICATION_PREFIX}${scan.id ?? Date.now()}`
    const notification = getScanNotification(scan, rawUrl)
    notificationTargets.set(notificationId, getHistoryUrl(clientId, rawUrl))

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
    )}&warning=${encodeURIComponent(getPrimaryWarning(scan))}`,
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
    return { status: 'Allowed', score: 100, blocked: false }
  }
  if (isMarkedSafeHost(host)) {
    const safeScan = {
      type: 'URL',
      target: rawUrl,
      score: 100,
      status: 'Safe',
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
    const response = await fetch(API_URL, {
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

    if (!response.ok) throw new Error(`Scanner returned ${response.status}`)
    const scan = await response.json()
    if (!previewOnly) remember(rawUrl, scan)
    await saveStatus({
      ok: true,
      lastUrl: rawUrl,
      lastStatus: scan.status,
      lastScore: scan.score,
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

async function recordBlockedVisit(rawUrl) {
  if (!isTrackableUrl(rawUrl)) return null
  await syncSafeHosts()
  const host = getHost(rawUrl)
  if (isAllowedHost(host)) {
    await unblockSite({ rawUrl, host })
    return { status: 'Allowed', score: 100, blocked: false }
  }
  if (hasBypass(host)) return { status: 'Allowed', score: 100, blocked: false }
  if (isMarkedSafeHost(host)) {
    await unblockSite({ rawUrl, host })
    return { status: 'Safe', score: 100, blocked: false }
  }

  const cooldownKey = `blocked-visit:${rawUrl}`
  if (getRecentScan(cooldownKey)) return null
  remember(cooldownKey, { status: 'recording' })

  try {
    const clientId = await getClientId()
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: rawUrl,
        source: 'browser-extension',
        reason: 'blocked-rule-hit',
        clientId,
      }),
    })

    if (!response.ok) throw new Error(`Scanner returned ${response.status}`)
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
    const clientId = await getClientId()
    const response = await fetch(EMAIL_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sender,
        subject,
        body,
        source: 'browser-email-monitor',
        clientId,
      }),
    })

    if (!response.ok) throw new Error(`Email scanner returned ${response.status}`)
    const scan = await response.json()
    await saveStatus({
      ok: true,
      lastUrl: sender || subject || 'Opened email',
      lastStatus: scan.status,
      lastScore: scan.score,
    })
    return scan
  } catch (error) {
    await saveStatus({
      ok: false,
      lastUrl: sender || subject || 'Opened email',
      error: error.message,
    })
    return { ok: false, error: error.message }
  }
}

chrome.tabs.onUpdated.addListener((_tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    scanUrl(tab.url, 'tab-complete', tab.id)
  }
})

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId)
    if (tab.url) scanUrl(tab.url, 'tab-activated', tab.id)
  } catch {
    // Tab may disappear before Chrome returns it.
  }
})

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    scanUrl(details.url, details.transitionType ?? 'navigation', details.tabId)
  }
})

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'scan-candidate-url' && message.url) {
    scanUrl(message.url, message.reason ?? 'content-script')
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
      .then((ok) => sendResponse({ ok }))
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

setInterval(syncSafeHosts, SAFE_HOST_SYNC_MS)
