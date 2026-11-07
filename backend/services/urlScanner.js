import { domainToUnicode } from 'node:url'
import { parse, getDomain as getRegistrableDomain } from 'tldts'
import { getRiskFromScore, recommendationsFor, scoreWarnings } from './riskScorer.js'
import urlLexicalModel from './urlLexicalModel.js'
import { lexicalProbability } from './urlLexicalFeatures.js'

export const MAX_URL_LENGTH = 8192
export const MAX_TEXT_LENGTH = 100000
export const MAX_LINKS = 100
const MAX_QUERY_PARAMETERS = 32
const MAX_QUERY_VALUE_LENGTH = 256
const pslOptions = { allowPrivateDomains: true }

export const piracySiteIndicators = [
  'dodi',
  'dodi-repacks',
  'elamigos',
  'elamigos-games',
  'fitgirl',
  'fitgirl-repacks',
  'fitgirlrepacks',
  'game3rb',
  'gamedrive',
  'gog-games',
  'igg-games',
  'igggames',
  'kisskh',
  'oceanofgames',
  'online-fix',
  'ovagames',
  'repack-games',
  'steamrip',
  'steamunlocked',
  'thepiratebay',
]

const piracyTerms = /\b(?:piracy|pirated|torrents?|keygens?|warez|magnet[\s-]+links?|cracked[\s-]+(?:games?|software)|games?[\s-]+cracks?|repacks?)\b/i
const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const piracySitePattern = new RegExp(`(?:^|[^a-z0-9])(?:${piracySiteIndicators.map(escapeRegExp).join('|')})(?:[^a-z0-9]|$)`, 'i')

// Ownership suppresses only that brand's impersonation finding, never other rules.
export const officialDomains = {
  amazon: ['amazon.com', 'amazon.co.uk', 'amazon.co.jp', 'amazon.de', 'amazon.ca'],
  apple: ['apple.com', 'icloud.com'],
  bdo: ['bdo.com.ph'],
  bpi: ['bpi.com.ph'],
  facebook: ['facebook.com', 'fb.com'],
  gcash: ['gcash.com'],
  google: ['google.com', 'google.com.ph', 'google.co.uk', 'gmail.com'],
  maya: ['maya.ph', 'paymaya.com'],
  metrobank: ['metrobank.com.ph'],
  microsoft: ['microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com', 'office.com'],
  netflix: ['netflix.com'],
  paypal: ['paypal.com', 'paypal.me'],
  roblox: ['roblox.com'],
  shopee: ['shopee.ph', 'shopee.com', 'shopee.sg', 'shopee.com.my'],
  unionbank: ['unionbankph.com'],
}
const substitutions = { 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', х: 'x', і: 'i', у: 'y' }
const normalizeLookalikes = (value) => [...value].map((c) => substitutions[c] ?? c).join('')
const credentialWords = /(?:^|[^a-z])(?:login|log-in|signin|sign-in|verify|verification|password|passcode|otp|credentials|account|wallet|billing)(?:[^a-z]|$)/i
const lureWords = /(?:^|[-_.])(?:secure|security|support|login|verify|account|update|billing)(?:[-_.]|$)/i

// At most one edit; no matrix allocation or comparisons against short brands.
const oneEditApart = (left, right) => {
  if (Math.abs(left.length - right.length) > 1 || left === right) return false
  let i = 0
  let j = 0
  let edits = 0
  while (i < left.length && j < right.length) {
    if (left[i] === right[j]) { i++; j++; continue }
    if (++edits > 1) return false
    if (left.length >= right.length) i++
    if (right.length >= left.length) j++
  }
  return edits + Number(i < left.length || j < right.length) === 1
}

const parseUrl = (input) => {
  if (!input || input.length > MAX_URL_LENGTH || /\s/.test(input)) return null
  try {
    const url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(input) ? input : `https://${input}`)
    return ['http:', 'https:'].includes(url.protocol) ? url : null
  } catch { return null }
}

function queryBrandMentions(url) {
  if (!url) return []
  const brands = new Set(Object.keys(officialDomains))
  const mentions = new Set()
  let checked = 0
  for (const [, rawValue] of url.searchParams) {
    if (checked++ >= MAX_QUERY_PARAMETERS) break
    const value = rawValue.slice(0, MAX_QUERY_VALUE_LENGTH).toLowerCase()
    for (const brand of brands) {
      if (new RegExp(`(?:^|[^a-z0-9])${escapeRegExp(brand)}(?:$|[^a-z0-9])`, 'i').test(value)) mentions.add(brand)
    }
  }
  return [...mentions]
}

export function localCoverage(limitations = []) {
  return {
    status: 'local-only', checkedProviders: 0, totalProviders: 0,
    limitations: ['Reputation not checked.', 'Local heuristics cannot establish safety or verify ownership.', ...limitations],
  }
}

export function finding(code, label, deduction, evidence) {
  return { code, label, deduction, evidence }
}

export function contentCategories(text) {
  const categoryWarnings = []
  if (/\b(?:casino|gambling|betting|sportsbook|roulette|baccarat|sabong|bet365|1xbet|bingoplus)\b/i.test(text)) {
    categoryWarnings.push({ category: 'gambling-content', label: 'Contains gambling-related references; this is not a phishing determination.' })
  }
  if (piracyTerms.test(text) || piracySitePattern.test(text)) {
    categoryWarnings.push({ category: 'piracy-content', label: 'Contains piracy-related references; this is not a phishing determination.' })
  }
  return categoryWarnings
}

export function localResult(findings, details, kind, score = scoreWarnings(findings)) {
  const risk = getRiskFromScore(score)
  const warningFindings = findings.filter((item) => !(item.code === 'query-brand-mention' && Number(item.deduction) === 0))
  const categoryWarnings = details.categoryWarnings ?? []
  const categories = [...new Set([
    ...(findings.some((item) => item.deduction > 0) ? ['phishing-indicators'] : []),
    ...categoryWarnings.map((item) => item.category),
  ])]
  const recommendations = recommendationsFor(risk.status, categories)
  return {
    ...risk, score,
    summary: warningFindings.length ? `Found ${warningFindings.length} local ${kind} warning sign${warningFindings.length === 1 ? '' : 's'}.` : `No strong local ${kind} phishing indicators were found. Reputation was not checked.`,
    warningSigns: [...new Set(warningFindings.map((item) => item.label))],
    recommendations, recommendation: recommendations.join(' '),
    details: {
      ...details, findings, categoryWarnings,
      categories,
    },
  }
}

// Preserve the existing hostname helper contract; PSL domain is in scan details.
export function getDomain(target) {
  return parseUrl(String(target ?? '').trim())?.hostname ?? String(target ?? '').slice(0, MAX_URL_LENGTH)
}

export function scanUrl(urlInput) {
  const raw = String(urlInput ?? '').trim()
  const target = raw.slice(0, MAX_URL_LENGTH)
  const url = raw.length <= MAX_URL_LENGTH ? parseUrl(target) : null
  const host = url?.hostname.toLowerCase().replace(/\.$/, '') ?? ''
  const parsed = parse(host, pslOptions)
  const domain = getRegistrableDomain(host, pslOptions)
  const name = parsed.domainWithoutSuffix ?? ''
  let decoded = `${url?.pathname ?? ''}${url?.search ?? ''}`
  try { decoded = decodeURIComponent(decoded) } catch { /* Keep malformed escapes as evidence. */ }
  let decodedPath = url?.pathname ?? ''
  try { decodedPath = decodeURIComponent(decodedPath) } catch { /* Keep malformed escapes as evidence. */ }
  const credentialContext = credentialWords.test(`${host} ${decoded}`)
  const hostnameCredentialContext = credentialWords.test(`${host} ${decodedPath}`)
  const parsedQueryBrands = queryBrandMentions(url)
  const brandCredentialContext = parsedQueryBrands.length ? hostnameCredentialContext : credentialContext
  const findings = []
  const limitations = ['Page content, redirects, and domain registration were not checked.']
  if (raw.length > MAX_URL_LENGTH) limitations.push(`URL exceeds the ${MAX_URL_LENGTH}-character local limit and was not parsed.`)
  if (!url || (!domain && !parsed.isIp)) {
    findings.push(finding('invalid-url', 'URL could not be fully interpreted as a web address', 22, { input: target.slice(0, 200) }))
  }

  const unicodeName = domainToUnicode(name)
  const labels = (parsed.subdomain ?? '').split('.').filter(Boolean)
  const tokens = unicodeName.split(/[-_]/)
  const candidates = [unicodeName, ...tokens].filter((token) => token.length <= 64)
  let brandFinding = null
  const hostnameBrandMatches = new Set()
  const independentHostnameBrandMatches = new Set()
  for (const [brand, owners] of Object.entries(officialDomains)) {
    if (owners.includes(domain)) continue
    const exact = name === brand || labels.includes(brand)
    const compound = (brandCredentialContext || lureWords.test(name)) && (tokens.includes(brand) || name === `${brand}secure` || name === `${brand}login`)
    const lookalike = brand.length >= 5 && candidates.some((candidate) =>
      candidate !== brand && (normalizeLookalikes(candidate) === brand || (brandCredentialContext && oneEditApart(candidate, brand))))
    if (!exact && !compound && !lookalike) continue
    hostnameBrandMatches.add(brand)
    const independentCompound = (hostnameCredentialContext || lureWords.test(name)) && (tokens.includes(brand) || name === `${brand}secure` || name === `${brand}login`)
    const independentLookalike = brand.length >= 5 && candidates.some((candidate) =>
      candidate !== brand && (normalizeLookalikes(candidate) === brand || (hostnameCredentialContext && oneEditApart(candidate, brand))))
    if (exact || independentCompound || independentLookalike) independentHostnameBrandMatches.add(brand)
    const deduction = exact || compound ? 40 : 30
    if (!brandFinding || deduction > brandFinding.deduction) {
      brandFinding = finding('brand-impersonation', `Possible ${brand} impersonation on an unrelated registrable domain`, deduction, {
        brand, hostname: host, registrableDomain: domain, matchedBy: exact ? 'brand-label' : compound ? 'brand-with-lure' : 'bounded-lookalike',
      })
    }
  }
  if (brandFinding) findings.push(brandFinding)
  // MMDA/NCAP impersonation often uses several government abbreviations in
  // an unrelated commercial domain rather than a conventional brand label.
  // Require a combined authority pattern (or an authority marker plus traffic
  // enforcement language); a lone mention of MMDA is not enough.
  const isOfficialMmdaHost = host === 'mmda.gov.ph' || host.endsWith('.mmda.gov.ph')
  const mmdaMarker = /^(?:mmda|mmdancap)(?:$|[-0-9])/i.test(name)
  const ncapMarker = /ncap/i.test(name)
  const ltoMarker = /(?:^|-)lto(?:-|n)/i.test(name)
  const ncrMarker = /(?:^|-)ncr(?:-|$)/i.test(name)
  const enforcementContext = /(?:traffic|ticket|violation|citation|overdue|penalt(?:y|ies)|fine|settle|payment|ncap|ncr|lto)/i.test(`${decodedPath} ${url?.search ?? ''}`)
  const authorityCombination = mmdaMarker && (ncapMarker || ltoMarker || ncrMarker)
  if (url && domain && !isOfficialMmdaHost && mmdaMarker && (authorityCombination || enforcementContext)) {
    findings.push(finding(
      'brand-impersonation',
      'Possible MMDA/NCAP traffic-enforcement impersonation on an unrelated domain',
      30,
      { brand: 'MMDA/NCAP', hostname: host, registrableDomain: domain, matchedBy: authorityCombination ? 'combined-government-identifiers' : 'traffic-enforcement-context' },
    ))
  }
  // Catch deceptive account/profile URLs that put a known brand in the path
  // while hosting the page on an unrelated domain. Brand mentions by
  // themselves remain informational; require an account or action route.
  const pathImpersonationContext = /(?:^|[^a-z0-9])(?:account|profile|user|login|log-in|signin|sign-in|verify|verification|password|wallet|billing|payment|recover|recovery|member|identity|claim|secure)(?:$|[^a-z0-9])/i.test(decodedPath)
  if (url && domain && pathImpersonationContext) {
    for (const [brand, owners] of Object.entries(officialDomains)) {
      const isOfficialBrandHost = owners.some((officialDomain) => host === officialDomain || host.endsWith(`.${officialDomain}`))
      if (isOfficialBrandHost || hostnameBrandMatches.has(brand)) continue
      const escapedBrand = escapeRegExp(brand)
      const brandInPath = new RegExp(`(?:^|[^a-z0-9])${escapedBrand}(?:$|[^a-z0-9])`, 'i').test(decodedPath)
      if (!brandInPath) continue
      findings.push(finding(
        'brand-impersonation',
        `Possible ${brand} impersonation in an account-related URL path on an unrelated domain`,
        30,
        { brand, hostname: host, registrableDomain: domain, matchedBy: 'brand-in-deceptive-path' },
      ))
      break
    }
  }
  if (url?.username || url?.password) {
    findings.push(finding('url-userinfo', 'URL includes credentials or text before @ that can conceal the destination', 30, { hostname: host, hasUsername: Boolean(url.username), hasPassword: Boolean(url.password) }))
    let username = url.username
    try { username = decodeURIComponent(username) } catch { /* Use original username. */ }
    if (/[.]/.test(username) || Object.keys(officialDomains).some((brand) => username.toLowerCase().includes(brand))) {
      findings.push(finding('deceptive-userinfo', 'URL username resembles a trusted destination but the actual host follows @', 25, { hostname: host }))
    }
  }
  if (credentialContext && (brandFinding || url?.username || parsed.isIp)) {
    findings.push(finding('credential-lure', 'Credential wording accompanies destination deception or an IP address', 20, { hostname: host, context: 'credential-related URL wording' }))
  }
  if (parsed.isIp) findings.push(finding('ip-destination', 'URL uses an IP address; its owner cannot be inferred from a domain', 10, { hostname: host }))
  if (host.split('.').some((label) => label.startsWith('xn--')) && (brandFinding || credentialContext)) {
    findings.push(finding('contextual-idn', 'Internationalized domain appears with credential or impersonation indicators', 10, { hostname: host }))
  }
  if (url?.protocol === 'http:' && findings.some((item) => item.deduction >= 20)) {
    findings.push(finding('unencrypted-context', 'An already concerning URL also uses unencrypted HTTP', 5, { protocol: 'http:' }))
  }
  if (url && domain) {
    const probability = lexicalProbability(target, urlLexicalModel)
    const officialOwner = Object.values(officialDomains).some((owners) => owners.includes(domain))
    const structuralSignals = [
      target.length >= 80,
      labels.length >= 3,
      !host.includes('xn--') && (host.match(/-/g) ?? []).length >= 2,
      ((target.match(/\d/g) ?? []).length / Math.max(1, target.length)) >= 0.12,
      url.search.length >= 20,
      url.pathname.split('/').filter(Boolean).length >= 5,
    ].filter(Boolean).length
    const modelSupported = !officialOwner && structuralSignals > 0
    // The learned value is uncalibrated and cannot establish a block by itself.
    // Require independent structural support and the zero-training-FP threshold.
    const deduction = modelSupported && probability >= urlLexicalModel.blockThreshold ? 25 : 0
    if (deduction) findings.push(finding(
      'external-url-model',
      'URL pattern resembles labeled phishing URLs',
      deduction,
      { model: 'phiusiil-url-lexical-v1', phishingLikelihood: Number(probability.toFixed(4)), structuralSignals, calibration: 'uncalibrated' },
    ))
  }
  if (url && (domain || parsed.isIp)) {
    const queryBrands = parsedQueryBrands
    if (queryBrands.length) {
      const corroboratingSignals = [
        ...(independentHostnameBrandMatches.size ? ['hostname-brand-match'] : []),
        ...(url.username || url.password ? ['userinfo-structure'] : []),
        ...(parsed.isIp ? ['ip-destination'] : []),
        ...(host.split('.').some((label) => label.startsWith('xn--')) && hostnameCredentialContext ? ['contextual-idn'] : []),
      ]
      // Corroborate only with hostname/path or URL-structure rules. Do not use
      // query-derived credential context or a model score that includes query text.
      let username = url.username.toLowerCase()
      try { username = decodeURIComponent(username) } catch { /* Retain the parser's encoded username. */ }
      const eligibleBrands = queryBrands.filter((brand) =>
        !hostnameBrandMatches.has(brand) && !officialDomains[brand].includes(domain) && !username.includes(brand))
      const riskBrands = corroboratingSignals.length ? eligibleBrands : []
      const diagnosticBrands = queryBrands.filter((brand) => !riskBrands.includes(brand))
      const evidence = (brands) => ({
        brands,
        hostname: host,
        registrableDomain: domain,
        matchedBy: 'query-parameter-value',
        parameterLimit: MAX_QUERY_PARAMETERS,
        valueLengthLimit: MAX_QUERY_VALUE_LENGTH,
      })
      if (riskBrands.length) {
        findings.push(finding(
          'brand-query-impersonation',
          `Known ${riskBrands.join(', ')} brand in a URL query accompanies suspicious context on an unrelated host`,
          25,
          { ...evidence(riskBrands), corroboration: corroboratingSignals },
        ))
      }
      if (diagnosticBrands.length) {
        findings.push(finding(
          'query-brand-mention',
          `Known brand ${diagnosticBrands.join(', ')} appears in a URL query; no separate risk contribution was added`,
          0,
          evidence(diagnosticBrands),
        ))
      }
    }
  }
  return localResult(findings, {
    domain: host, registrableDomain: domain, publicSuffix: parsed.publicSuffix,
    coverage: localCoverage(limitations), categoryWarnings: contentCategories(`${host} ${decoded}`),
  }, 'URL')
}
