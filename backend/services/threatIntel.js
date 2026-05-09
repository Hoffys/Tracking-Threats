import { addWarning, getRiskFromScore, recommendationsFor, scoreWarnings } from './riskScorer.js'

const requestTimeoutMs = 4500

const withTimeout = async (url, options) => {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), requestTimeoutMs)

  try {
    return await fetch(url, { ...options, signal: controller.signal })
  } finally {
    clearTimeout(timeout)
  }
}

const getUrlIdentifier = (target) =>
  Buffer.from(target).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

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

export async function enrichUrlAnalysis(target, baseAnalysis) {
  const results = await Promise.allSettled([
    checkVirusTotal(target),
    checkGoogleSafeBrowsing(target),
  ])

  const providerResults = results.map((result, index) => {
    if (result.status === 'fulfilled') return result.value
    return {
      provider: index === 0 ? 'VirusTotal' : 'Google Safe Browsing',
      checked: true,
      error: result.reason?.message ?? 'Threat intelligence lookup failed',
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
