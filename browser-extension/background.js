const API_URL = 'http://localhost:4000/api/scan/url'
const APP_URL = 'http://localhost:5173/'
const COOLDOWN_MS = 15000
const MAX_TRACKED = 200

const recentScans = new Map()

function isTrackableUrl(rawUrl) {
  try {
    const url = new URL(rawUrl)
    if (!['http:', 'https:'].includes(url.protocol)) return false
    if (['localhost', '127.0.0.1'].includes(url.hostname)) return false
    return true
  } catch {
    return false
  }
}

function remember(url) {
  recentScans.set(url, Date.now())
  if (recentScans.size > MAX_TRACKED) {
    const oldest = recentScans.keys().next().value
    recentScans.delete(oldest)
  }
}

function isRecentlyScanned(url) {
  const previous = recentScans.get(url)
  return previous && Date.now() - previous < COOLDOWN_MS
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

async function scanUrl(rawUrl, reason = 'navigation') {
  if (!isTrackableUrl(rawUrl) || isRecentlyScanned(rawUrl)) return

  remember(rawUrl)
  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: rawUrl,
        source: 'browser-extension',
        reason,
      }),
    })

    if (!response.ok) throw new Error(`Scanner returned ${response.status}`)
    const scan = await response.json()
    await saveStatus({
      ok: true,
      lastUrl: rawUrl,
      lastStatus: scan.status,
      lastScore: scan.score,
    })
  } catch (error) {
    await saveStatus({
      ok: false,
      lastUrl: rawUrl,
      error: error.message,
    })
  }
}

chrome.tabs.onUpdated.addListener((_tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    scanUrl(tab.url, 'tab-complete')
  }
})

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId)
    if (tab.url) scanUrl(tab.url, 'tab-activated')
  } catch {
    // Tab may disappear before Chrome returns it.
  }
})

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    scanUrl(details.url, details.transitionType ?? 'navigation')
  }
})
