const API_URL = 'http://localhost:4000/api/scan/url'
const EMAIL_API_URL = 'http://localhost:4000/api/scan/email'
const SAFE_HOSTS_URL = 'http://localhost:4000/api/safe-hosts'
const APP_URL = 'http://localhost:5173/'
const COOLDOWN_MS = 15000
const SAFE_HOST_SYNC_MS = 5000
const MAX_TRACKED = 200
const BLOCK_RULE_ID_BASE = 10000
const MAX_BLOCK_RULES = 250
const UNBLOCK_BYPASS_MS = 30000
const BLOCK_CONTEXT_TTL_MS = 5 * 60 * 1000
const PASS_THROUGH_HOSTS = new Set([
  'bing.com',
  'duckduckgo.com',
  'google.com',
  'search.yahoo.com',
])

const recentScans = new Map()
let blockedHosts = new Map()
const bypassHosts = new Map()
let safeHosts = new Set()

async function loadBlockedHosts() {
  const stored = await chrome.storage.local.get('blockedHosts')
  blockedHosts = new Map(stored.blockedHosts ?? [])
}

async function saveBlockedHosts() {
  await chrome.storage.local.set({
    blockedHosts: Array.from(blockedHosts.entries()),
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
    return false
  }
  return true
}

async function rememberBlockedSite(rawUrl, scan = null) {
  const host = getHost(rawUrl)
  if (!host) return
  if (isMarkedSafeHost(host)) return

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
  const ruleId = blockedHosts.get(host)
  if (!host) return false

  bypassHosts.set(host, Date.now() + UNBLOCK_BYPASS_MS)

  if (!ruleId) return true

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [ruleId],
  })
  blockedHosts.delete(host)
  await saveBlockedHosts()
  return true
}

async function saveStatus(status) {
  await chrome.storage.local.set({
    threattrackStatus: {
      ...status,
      updatedAt: new Date().toISOString(),
      appUrl: APP_URL,
    },
  })
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
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: rawUrl,
        source: 'browser-extension',
        reason,
        preview: previewOnly,
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
  if (isMarkedSafeHost(getHost(rawUrl))) {
    await unblockSite({ rawUrl, host: getHost(rawUrl) })
    return { status: 'Safe', score: 100, blocked: false }
  }

  const cooldownKey = `blocked-visit:${rawUrl}`
  if (getRecentScan(cooldownKey)) return null
  remember(cooldownKey, { status: 'recording' })

  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: rawUrl,
        source: 'browser-extension',
        reason: 'blocked-rule-hit',
      }),
    })

    if (!response.ok) throw new Error(`Scanner returned ${response.status}`)
    const scan = await response.json()
    remember(rawUrl, scan)
    await rememberBlockedSite(rawUrl, scan)
    await saveStatus({
      ok: true,
      lastUrl: rawUrl,
      lastStatus: scan.status,
      lastScore: scan.score,
    })
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
    const response = await fetch(EMAIL_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sender,
        subject,
        body,
        source: 'browser-email-monitor',
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

  return false
})

chrome.storage.local.remove('allowedHosts')

loadBlockedHosts()
  .then(syncSafeHosts)
  .then(clearPassThroughBlockRules)
  .then(syncBlockRules)
  .catch(() => {
    // Storage may be temporarily unavailable during extension startup.
  })

setInterval(syncSafeHosts, SAFE_HOST_SYNC_MS)
