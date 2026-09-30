export const categoryLabels = {
  'phishing-indicators': 'Phishing indicators',
  'malware-reputation': 'Malware reputation',
  'ip-reputation': 'IP reputation',
  'gambling-content': 'Gambling content',
  'piracy-content': 'Piracy content',
  'file-risk': 'File risk',
}

export function normalizeCategories(categories) {
  return Array.isArray(categories)
    ? [...new Set(categories.filter((category) => Object.hasOwn(categoryLabels, category)))]
    : []
}

export function normalizeCoverage(coverage) {
  const count = (value) => Number.isSafeInteger(value) && value >= 0
  if (!coverage || !['complete', 'partial', 'unavailable', 'local-only'].includes(coverage.status) ||
      !count(coverage.checkedProviders) || !count(coverage.totalProviders) ||
      coverage.checkedProviders > coverage.totalProviders) return undefined
  const result = {
    status: coverage.status,
    checkedProviders: coverage.checkedProviders,
    totalProviders: coverage.totalProviders,
    limitations: Array.isArray(coverage.limitations)
      ? coverage.limitations.filter((item) => typeof item === 'string').slice(0, 50)
      : [],
  }
  if (count(coverage.linksChecked) && count(coverage.totalLinks) && coverage.linksChecked <= coverage.totalLinks) {
    result.linksChecked = coverage.linksChecked
    result.totalLinks = coverage.totalLinks
  }
  // Inconsistent snapshots must not advertise complete checks.
  if (result.status === 'complete' && (result.checkedProviders < result.totalProviders ||
      result.linksChecked < result.totalLinks)) result.status = 'partial'
  return result
}

export function hasIncompleteChecks(coverage) {
  return normalizeCoverage(coverage)?.status !== 'complete'
}

export function riskLabel(risk, coverage) {
  if (risk === 'Safe') return hasIncompleteChecks(coverage) ? 'Incomplete checks' : 'No strong indicators'
  if (risk === 'Dangerous') return 'Risk detected'
  if (risk === 'Suspicious') return 'Caution'
  return risk
}

export function providerState(provider) {
  if (provider.error) return `Lookup unavailable - ${provider.error}`
  if (provider.skipped || provider.status === 'skipped') return 'Not checked - skipped'
  if (provider.checked === false) return 'Not checked'
  if (provider.found) return 'Matched'
  return provider.checked === true ? 'No match' : 'Check status unknown'
}

export function coverageLabel(coverage) {
  const value = normalizeCoverage(coverage)
  if (!value) return 'Coverage not recorded; checks cannot be verified.'
  const labels = { complete: 'Complete checks', partial: 'Incomplete checks', unavailable: 'Checks unavailable', 'local-only': 'Local checks only' }
  return `${labels[value.status]}: ${value.checkedProviders}/${value.totalProviders} providers checked` +
    (value.totalLinks === undefined ? '.' : `; ${value.linksChecked}/${value.totalLinks} links checked.`)
}

export function responseLabel(scan, manual = false) {
  if (manual || scan?.source === 'public-web-scan' || scan?.source === 'browser-search-preview') {
    return scan?.status === 'Dangerous' ? 'Risk detected; review recommended' : 'Review result'
  }
  if (scan?.blocked || scan?.responseStatus === 'Blocked') return 'Block policy recorded'
  return scan?.status === 'Dangerous' || scan?.status === 'Suspicious' ? 'Review recommended' : 'No block recorded'
}
