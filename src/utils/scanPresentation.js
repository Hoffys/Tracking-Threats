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

export function hasPiracyContent(categories) {
  return normalizeCategories(categories).includes('piracy-content')
}

export function hasContentWarnings(categories) {
  return normalizeCategories(categories).some((category) => category.endsWith('-content'))
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

export function riskLabel(risk, categories = []) {
  if (risk === 'Safe' && hasPiracyContent(categories)) return 'CAUTION - PIRACY RISK'
  if (risk === 'Safe' && hasContentWarnings(categories)) return 'Content warning - separate from phishing'
  if (risk === 'Safe') return 'Appears safe'
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

export function summarizeThreatIntelProviders(providers = []) {
  const groups = new Map()

  for (const provider of providers.filter(Boolean)) {
    const name = provider.provider || 'Unknown provider'
    const state = providerState(provider)
    const detail = provider.warning ? `${state} - ${provider.warning}` : state
    const group = groups.get(name) ?? { provider: name, total: 0, variants: new Map() }
    const variant = group.variants.get(detail) ?? { detail, count: 0 }
    variant.count += 1
    group.total += 1
    group.variants.set(detail, variant)
    groups.set(name, group)
  }

  return [...groups.values()].map((group) => ({
    provider: group.provider,
    summary: [...group.variants.values()].map((variant) => {
      if (group.total === 1) return variant.detail
      const count = variant.count === group.total
        ? `${group.total} checks`
        : `${variant.count} of ${group.total} checks`
      return `${variant.detail} (${count})`
    }).join('; '),
  }))
}

export function coverageLabel(coverage) {
  const value = normalizeCoverage(coverage)
  if (!value) return 'Scan finished. Check details were not recorded for this result; no further checks are pending.'
  const labels = { complete: 'All configured reputation checks responded', partial: 'Some reputation checks were unavailable or skipped', unavailable: 'Reputation checks were unavailable', 'local-only': 'Local analysis only' }
  return `Scan finished. ${labels[value.status]}. No further checks are pending. ${value.checkedProviders}/${value.totalProviders} providers checked` +
    (value.totalLinks === undefined ? '.' : `; ${value.linksChecked}/${value.totalLinks} links checked.`)
}

export function responseLabel(scan, manual = false) {
  if (manual || scan?.source === 'public-web-scan' || scan?.source === 'browser-search-preview') {
    return scan?.status === 'Dangerous' ? 'Risk detected; review recommended' : 'Review result'
  }
  if (scan?.blocked || scan?.responseStatus === 'Blocked') return 'Block policy recorded'
  return scan?.status === 'Dangerous' || scan?.status === 'Suspicious' ? 'Review recommended' : 'No block recorded'
}
