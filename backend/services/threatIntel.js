import dns from 'node:dns/promises'
import net from 'node:net'
import { addWarning, getRiskFromScore, recommendationsFor, scoreWarnings } from './riskScorer.js'

const requestTimeoutMs = 4500
const dnsTimeoutMs = 2500
const phishTankUserAgent = 'phishtank/tracking-threats'
const phishTankPassThroughHosts = new Set([
  'bing.com',
  'duckduckgo.com',
  'google.com',
  'search.yahoo.com',
  'www.bing.com',
  'www.google.com',
  'www.youtube.com',
  'youtube.com',
])

const withTimeout = async (url, options) => {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), requestTimeoutMs)

  try {
    return await fetch(url, { ...options, signal: controller.signal })
  } finally {
    clearTimeout(timeout)
  }
}

const formatProviderError = (error) => {
  const code = error?.cause?.code ?? error?.code
  const message = error?.cause?.message ?? error?.message ?? 'Threat intelligence lookup failed'

  if (code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
    return 'TLS certificate verification failed; restart the backend with Node system CA support'
  }

  if (error?.name === 'AbortError') {
    return 'Lookup timed out'
  }

  return code ? `${message} (${code})` : message
}

const getUrlIdentifier = (target) =>
  Buffer.from(target).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

const parseTarget = (target) => {
  try {
    return new URL(target.includes('://') ? target : `https://${target}`)
  } catch {
    return null
  }
}

const getHost = (target) => parseTarget(target)?.hostname.toLowerCase().replace(/^www\./, '') ?? ''

const isPrivateOrReservedIp = (value) => {
  if (net.isIP(value) === 4) {
    const parts = value.split('.').map(Number)
    const [first, second] = parts
    return (
      first === 10 ||
      first === 127 ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168) ||
      (first === 169 && second === 254) ||
      first === 0 ||
      first >= 224
    )
  }

  if (net.isIP(value) === 6) {
    const normalized = value.toLowerCase()
    return (
      normalized === '::1' ||
      normalized.startsWith('fc') ||
      normalized.startsWith('fd') ||
      normalized.startsWith('fe80:')
    )
  }

  return false
}

const withDnsTimeout = async (operation) => {
  let timeout
  try {
    return await Promise.race([
      operation,
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error('DNS lookup timed out')), dnsTimeoutMs)
      }),
    ])
  } finally {
    clearTimeout(timeout)
  }
}

const postForm = (url, values, extraHeaders = {}) =>
  withTimeout(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'TrackingThreats/1.0',
      ...extraHeaders,
    },
    body: new URLSearchParams(values),
  })

const requireUrlhausAuthKey = () => {
  const authKey = process.env.URLHAUS_AUTH_KEY
  if (!authKey) {
    throw new Error('Set URLHAUS_AUTH_KEY to enable URLhaus lookups')
  }

  return authKey
}

async function checkVirusTotal(target) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY
  if (!apiKey) return null

  const response = await withTimeout(
    `https://www.virustotal.com/api/v3/urls/${getUrlIdentifier(target)}`,
    {
      headers: {
        accept: 'application/json',
        'x-apikey': apiKey,
      },
    },
  )

  if (response.status === 404) {
    return {
      provider: 'VirusTotal',
      checked: true,
      found: false,
      warning: null,
      deduction: 0,
    }
  }

  if (!response.ok) throw new Error(`VirusTotal returned ${response.status}`)

  const payload = await response.json()
  const stats = payload?.data?.attributes?.last_analysis_stats ?? {}
  const malicious = Number(stats.malicious ?? 0)
  const suspicious = Number(stats.suspicious ?? 0)

  return {
    provider: 'VirusTotal',
    checked: true,
    found: true,
    stats,
    warning:
      malicious > 0
        ? `VirusTotal reports ${malicious} malicious engine detection${malicious === 1 ? '' : 's'}`
        : suspicious > 0
          ? `VirusTotal reports ${suspicious} suspicious engine detection${suspicious === 1 ? '' : 's'}`
          : null,
    deduction: malicious > 0 ? 55 : suspicious > 0 ? 25 : 0,
  }
}

async function checkGoogleSafeBrowsing(target) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY
  if (!apiKey) return null

  const response = await withTimeout(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: {
          clientId: 'tracking-threats',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION',
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: target }],
        },
      }),
    },
  )

  if (!response.ok) throw new Error(`Google Safe Browsing returned ${response.status}`)

  const payload = await response.json()
  const matches = payload.matches ?? []
  const threatTypes = [...new Set(matches.map((match) => match.threatType).filter(Boolean))]

  return {
    provider: 'Google Safe Browsing',
    checked: true,
    found: matches.length > 0,
    matches,
    warning:
      matches.length > 0
        ? `Google Safe Browsing matched ${threatTypes.join(', ') || 'known threat'}`
        : null,
    deduction: matches.length > 0 ? 60 : 0,
  }
}

async function checkUrlhausUrl(target) {
  const response = await postForm(
    'https://urlhaus-api.abuse.ch/v1/url/',
    { url: target },
    { 'Auth-Key': requireUrlhausAuthKey() },
  )

  if (response.status === 401 || response.status === 403) {
    throw new Error('URLhaus rejected URLHAUS_AUTH_KEY')
  }
  if (!response.ok) throw new Error(`URLhaus URL lookup returned ${response.status}`)

  const payload = await response.json()
  const listed = payload.query_status === 'ok'
  const tags = Array.isArray(payload.tags) ? payload.tags.filter(Boolean) : []
  const threat = payload.threat || tags.join(', ') || 'malware distribution'

  return {
    provider: 'URLhaus URL',
    checked: true,
    found: listed,
    status: payload.url_status,
    threat,
    tags,
    warning: listed ? `URLhaus lists this URL for ${threat}` : null,
    deduction: listed ? 65 : 0,
  }
}

async function checkUrlhausHost(target) {
  const host = getHost(target)
  if (!host || net.isIP(host)) return null

  const response = await postForm(
    'https://urlhaus-api.abuse.ch/v1/host/',
    { host },
    { 'Auth-Key': requireUrlhausAuthKey() },
  )

  if (response.status === 401 || response.status === 403) {
    throw new Error('URLhaus rejected URLHAUS_AUTH_KEY')
  }
  if (!response.ok) throw new Error(`URLhaus host lookup returned ${response.status}`)

  const payload = await response.json()
  const listed = payload.query_status === 'ok'
  const activeUrls = Number(payload.urls?.length ?? 0)

  return {
    provider: 'URLhaus Host',
    checked: true,
    found: listed,
    host,
    urlCount: activeUrls,
    warning: listed
      ? `URLhaus reports malware URLs hosted on ${host}${activeUrls ? ` (${activeUrls} recent URL${activeUrls === 1 ? '' : 's'})` : ''}`
      : null,
    deduction: listed ? 55 : 0,
  }
}

async function checkPhishTank(target) {
  if (phishTankPassThroughHosts.has(parseTarget(target)?.hostname.toLowerCase())) return null

  const appKey = process.env.PHISHTANK_APP_KEY
  const response = await postForm('https://checkurl.phishtank.com/checkurl/', {
    format: 'json',
    url: target,
    ...(appKey ? { app_key: appKey } : {}),
  }, {
    'User-Agent': phishTankUserAgent,
  })

  if (response.status === 509) {
    throw new Error('PhishTank rate limit reached; set PHISHTANK_APP_KEY')
  }
  if (!response.ok) throw new Error(`PhishTank returned ${response.status}`)

  const payload = await response.json()
  const results = payload.results ?? {}
  const listed = Boolean(results.in_database)
  const verified = Boolean(results.verified)

  return {
    provider: 'PhishTank',
    checked: true,
    found: listed,
    verified,
    phishId: results.phish_id,
    warning: listed
      ? `PhishTank ${verified ? 'verified' : 'reported'} this URL as phishing`
      : null,
    deduction: verified ? 60 : listed ? 42 : 0,
  }
}

async function resolveHostAddresses(host) {
  if (!host) return { addresses: [], errors: [] }
  if (net.isIP(host)) return { addresses: [host], errors: [] }

  try {
    const results = await withDnsTimeout(dns.lookup(host, { all: true }))
    const addresses = [...new Set(results.map((result) => result.address).filter(Boolean))]
    return { addresses, errors: [] }
  } catch (error) {
    if (['ENODATA', 'ENOTFOUND', 'ENODOMAIN'].includes(error?.code)) {
      return { addresses: [], errors: [error] }
    }

    throw error
  }
}

async function checkDnsReputation(target) {
  const host = getHost(target)
  if (!host) return null

  const { addresses } = await resolveHostAddresses(host)
  const privateAddresses = addresses.filter(isPrivateOrReservedIp)
  const hasNoPublicAddress = addresses.length === 0

  return {
    provider: 'DNS Reputation',
    checked: true,
    found: privateAddresses.length > 0 || hasNoPublicAddress,
    host,
    addresses: addresses.slice(0, 8),
    warning:
      privateAddresses.length > 0
        ? `Domain resolves to private or reserved network address ${privateAddresses[0]}`
        : hasNoPublicAddress
          ? 'Domain has no public A or AAAA DNS records'
          : null,
    deduction: privateAddresses.length > 0 ? 35 : hasNoPublicAddress ? 12 : 0,
  }
}

async function checkAbuseIpDb(target) {
  const apiKey = process.env.ABUSEIPDB_API_KEY
  if (!apiKey) return null

  const host = getHost(target)
  const { addresses } = await resolveHostAddresses(host)
  const publicAddress = addresses.find((address) => !isPrivateOrReservedIp(address))
  if (!publicAddress) return null

  const response = await withTimeout(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(
      publicAddress,
    )}&maxAgeInDays=90&verbose=true`,
    {
      headers: {
        accept: 'application/json',
        key: apiKey,
      },
    },
  )

  if (!response.ok) throw new Error(`AbuseIPDB returned ${response.status}`)

  const payload = await response.json()
  const data = payload.data ?? {}
  const confidence = Number(data.abuseConfidenceScore ?? 0)

  return {
    provider: 'AbuseIPDB',
    checked: true,
    found: confidence > 0,
    ipAddress: publicAddress,
    abuseConfidenceScore: confidence,
    totalReports: data.totalReports,
    countryCode: data.countryCode,
    warning:
      confidence > 0
        ? `AbuseIPDB reports ${confidence}% abuse confidence for host IP ${publicAddress}`
        : null,
    deduction: confidence >= 80 ? 50 : confidence >= 25 ? 25 : confidence > 0 ? 10 : 0,
  }
}

export async function enrichUrlAnalysis(target, baseAnalysis) {
  const checks = [
    { provider: 'VirusTotal', run: () => checkVirusTotal(target) },
    { provider: 'Google Safe Browsing', run: () => checkGoogleSafeBrowsing(target) },
    { provider: 'URLhaus URL', run: () => checkUrlhausUrl(target) },
    { provider: 'URLhaus Host', run: () => checkUrlhausHost(target) },
    { provider: 'PhishTank', run: () => checkPhishTank(target) },
    { provider: 'DNS Reputation', run: () => checkDnsReputation(target) },
    { provider: 'AbuseIPDB', run: () => checkAbuseIpDb(target) },
  ]

  const results = await Promise.allSettled(checks.map((check) => check.run()))

  const providerResults = results.map((result, index) => {
    if (result.status === 'fulfilled') return result.value
    return {
      provider: checks[index].provider,
      checked: true,
      error: formatProviderError(result.reason),
    }
  })

  const activeResults = providerResults.filter(Boolean)
  const externalWarnings = []
  for (const result of activeResults) {
    addWarning(externalWarnings, Boolean(result.warning), result.warning, result.deduction ?? 0)
  }

  const score = scoreWarnings([
    ...(baseAnalysis.warningSigns ?? []).map((label) => ({ label, deduction: 0 })),
    ...externalWarnings,
  ])
  const finalScore = Math.min(baseAnalysis.score, score)
  const risk = getRiskFromScore(finalScore)
  const recommendations = recommendationsFor(risk.status)
  const warningSigns = [
    ...(baseAnalysis.warningSigns ?? []),
    ...externalWarnings.map((warning) => warning.label),
  ]

  return {
    ...baseAnalysis,
    ...risk,
    score: finalScore,
    summary:
      warningSigns.length > 0
        ? `Found ${warningSigns.length} URL warning sign${warningSigns.length === 1 ? '' : 's'}.`
        : baseAnalysis.summary,
    warningSigns,
    recommendations,
    recommendation: recommendations.join(' '),
    details: {
      ...(baseAnalysis.details ?? {}),
      threatIntel: activeResults,
    },
  }
}
