import { addWarning, getRiskFromScore, recommendationsFor, scoreWarnings } from './riskScorer.js'

const suspiciousTlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top']
const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
const protectedBrands = ['google', 'facebook', 'paypal', 'amazon', 'microsoft', 'apple']
const substitutions = { 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', '@': 'a', '$': 's' }

const parseUrl = (input) => {
  try {
    return new URL(input.includes('://') ? input : `https://${input}`)
  } catch {
    return null
  }
}

const normalizeLookalikes = (value) =>
  value
    .toLowerCase()
    .split('')
    .map((character) => substitutions[character] ?? character)
    .join('')

const getRegistrableName = (host) => {
  const parts = host.replace(/^www\./, '').split('.')
  return parts.length >= 2 ? parts.at(-2) : parts[0]
}

const distance = (left, right) => {
  const rows = Array.from({ length: left.length + 1 }, (_, row) => [row])
  for (let column = 1; column <= right.length; column += 1) rows[0][column] = column
  for (let row = 1; row <= left.length; row += 1) {
    for (let column = 1; column <= right.length; column += 1) {
      const cost = left[row - 1] === right[column - 1] ? 0 : 1
      rows[row][column] = Math.min(
        rows[row - 1][column] + 1,
        rows[row][column - 1] + 1,
        rows[row - 1][column - 1] + cost,
      )
    }
  }
  return rows[left.length][right.length]
}

const hasTyposquatting = (host) => {
  const domain = getRegistrableName(host)
  const normalized = normalizeLookalikes(domain)
  return protectedBrands.some((brand) => {
    if (domain === brand) return false
    return normalized === brand || normalized.includes(brand) || distance(normalized, brand) <= 2
  })
}

export function getDomain(target) {
  return parseUrl(target)?.hostname ?? target
}

export function scanUrl(urlInput) {
  const target = urlInput.trim()
  const url = parseUrl(target)
  const host = url?.hostname.toLowerCase() ?? target.toLowerCase()
  const path = url?.pathname.toLowerCase() ?? ''
  const tld = host.split('.').at(-1)
  const warnings = []

  addWarning(warnings, !url, 'URL format is malformed or incomplete', 18)
  addWarning(warnings, url?.protocol !== 'https:', 'URL does not use HTTPS', 16)
  addWarning(warnings, suspiciousTlds.includes(tld), `Uses suspicious .${tld} top-level domain`, 18)
  addWarning(warnings, /^\d{1,3}(\.\d{1,3}){3}$/.test(host), 'Uses an IP address instead of a domain name', 25)
  addWarning(warnings, shorteners.includes(host.replace(/^www\./, '')), 'Uses a URL shortener', 20)
  addWarning(warnings, hasTyposquatting(host), 'Possible typosquatting of a trusted brand', 25)
  addWarning(warnings, /login|verify|signin|account|password/.test(path), 'URL contains credential or account keywords', 14)

  const score = scoreWarnings(warnings)
  const risk = getRiskFromScore(score)
  const recommendations = recommendationsFor(risk.status)

  return {
    ...risk,
    score,
    summary:
      warnings.length > 0
        ? `Found ${warnings.length} URL warning sign${warnings.length === 1 ? '' : 's'}.`
        : 'No strong URL phishing indicators were found.',
    warningSigns: warnings.map((warning) => warning.label),
    recommendations,
    recommendation: recommendations.join(' '),
    details: { domain: host },
  }
}
