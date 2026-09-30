import { domainToUnicode } from 'node:url'
import { parse, getDomain as getRegistrableDomain } from 'tldts'
import { getRiskFromScore, recommendationsFor, scoreWarnings } from './riskScorer.js'

export const MAX_URL_LENGTH = 8192
export const MAX_TEXT_LENGTH = 100000
export const MAX_LINKS = 100
const pslOptions = { allowPrivateDomains: true }

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
  if (/\b(?:piracy|pirated|torrent|torrents|keygen|warez|cracked[\s-]+software|fitgirl(?:-repacks)?|steamunlocked|thepiratebay|dodi-repacks)\b/i.test(text)) {
    categoryWarnings.push({ category: 'piracy-content', label: 'Contains piracy-related references; this is not a phishing determination.' })
  }
  return categoryWarnings
}

export function localResult(findings, details, kind, score = scoreWarnings(findings)) {
  const risk = getRiskFromScore(score)
  const recommendations = recommendationsFor(risk.status)
  const categoryWarnings = details.categoryWarnings ?? []
  return {
    ...risk, score,
    summary: findings.length ? `Found ${findings.length} local ${kind} warning sign${findings.length === 1 ? '' : 's'}.` : `No strong local ${kind} phishing indicators were found. Reputation was not checked.`,
    warningSigns: [...new Set(findings.map((item) => item.label))],
    recommendations, recommendation: recommendations.join(' '),
    details: {
      ...details, findings, categoryWarnings,
      categories: [...new Set([
        ...(findings.some((item) => item.deduction > 0) ? ['phishing-indicators'] : []),
        ...categoryWarnings.map((item) => item.category),
      ])],
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
  const credentialContext = credentialWords.test(`${host} ${decoded}`)
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
  for (const [brand, owners] of Object.entries(officialDomains)) {
    if (owners.includes(domain)) continue
    const exact = name === brand || labels.includes(brand)
    const compound = (credentialContext || lureWords.test(name)) && (tokens.includes(brand) || name === `${brand}secure` || name === `${brand}login`)
    const lookalike = brand.length >= 5 && candidates.some((candidate) =>
      candidate !== brand && (normalizeLookalikes(candidate) === brand || (credentialContext && oneEditApart(candidate, brand))))
    if (!exact && !compound && !lookalike) continue
    const deduction = exact || compound ? 40 : 30
    if (!brandFinding || deduction > brandFinding.deduction) {
      brandFinding = finding('brand-impersonation', `Possible ${brand} impersonation on an unrelated registrable domain`, deduction, {
        brand, hostname: host, registrableDomain: domain, matchedBy: exact ? 'brand-label' : compound ? 'brand-with-lure' : 'bounded-lookalike',
      })
    }
  }
  if (brandFinding) findings.push(brandFinding)
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
  return localResult(findings, {
    domain: host, registrableDomain: domain, publicSuffix: parsed.publicSuffix,
    coverage: localCoverage(limitations), categoryWarnings: contentCategories(`${host} ${decoded}`),
  }, 'URL')
}
