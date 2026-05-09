const MAX_RESULTS_TO_SCAN = 12
const GOOGLE_REDIRECT_PATHS = new Set(['/url', '/interstitial'])

function normalizeCandidate(rawHref) {
  try {
    const url = new URL(rawHref, window.location.href)
    if (url.hostname === 'www.google.com' && GOOGLE_REDIRECT_PATHS.has(url.pathname)) {
      const redirected = url.searchParams.get('q') ?? url.searchParams.get('url')
      return redirected ? normalizeCandidate(redirected) : null
    }

    if (!['http:', 'https:'].includes(url.protocol)) return null
    if (url.hostname.endsWith('google.com')) return null
    return url.href
  } catch {
    return null
  }
}

function collectResultLinks() {
  const candidates = new Set()

  document.querySelectorAll('a[href]').forEach((anchor) => {
    const href = anchor.getAttribute('href')
    const normalized = href ? normalizeCandidate(href) : null
    if (normalized) candidates.add(normalized)
  })

  return Array.from(candidates).slice(0, MAX_RESULTS_TO_SCAN)
}

function scanGoogleResults() {
  collectResultLinks().forEach((url) => {
    chrome.runtime.sendMessage({
      type: 'scan-candidate-url',
      url,
      reason: 'google-search-result',
    })
  })
}

scanGoogleResults()
