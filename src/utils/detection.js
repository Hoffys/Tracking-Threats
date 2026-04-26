const statusFromScore = (score) => {
  if (score >= 80) return { status: 'Safe', risk: 'low' }
  if (score >= 50) return { status: 'Suspicious', risk: 'medium' }
  return { status: 'Dangerous', risk: 'critical' }
}

const recommendationsByStatus = {
  Safe: [
    'Proceed with normal caution.',
    'Keep sender and link context in mind before sharing sensitive information.',
  ],
  Suspicious: [
    'Do not submit credentials until the source is verified.',
    'Check the sender or domain through a trusted channel.',
    'Open links only from a clean browser session if review is required.',
  ],
  Dangerous: [
    'Do not open the link or attachment.',
    'Quarantine the message and report it to security.',
    'Verify any account or payment request using an official website or phone number.',
  ],
}

const clampScore = (score) => Math.max(0, Math.min(100, score))

const addWarning = (warnings, condition, label, deduction) => {
  if (condition) {
    warnings.push({ label, deduction })
  }
}

const parseUrl = (input) => {
  const trimmed = input.trim()
  try {
    return new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`)
  } catch {
    return null
  }
}

const suspiciousTlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top']
const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
const protectedBrands = ['google', 'facebook', 'paypal', 'amazon', 'microsoft', 'apple']
const substitutions = { 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', '@': 'a', '$': 's' }

const levenshtein = (left, right) => {
  const rows = Array.from({ length: left.length + 1 }, (_, index) => [index])

  for (let column = 1; column <= right.length; column += 1) {
    rows[0][column] = column
  }

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

const hasTyposquatting = (host) => {
  const domainName = getRegistrableName(host)
  const normalizedName = normalizeLookalikes(domainName)

  return protectedBrands.some((brand) => {
    if (domainName === brand) return false
    return (
      normalizedName === brand ||
      domainName.includes(brand) ||
      normalizedName.includes(brand) ||
      levenshtein(normalizedName, brand) <= 2
    )
  })
}

export const extractLinks = (text) => text.match(/https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi) ?? []

export function scanUrl(input) {
  const value = input.trim()
  const url = parseUrl(value)
  const host = url?.hostname.toLowerCase() ?? value.toLowerCase()
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
  addWarning(warnings, host.split('.').length >= 4, 'Contains excessive subdomains', 8)
  addWarning(warnings, /%[0-9a-f]{2}/i.test(value), 'Contains encoded characters that may hide the destination', 8)
  addWarning(warnings, value.length > 90, 'URL is unusually long', 6)

  const score = clampScore(
    100 - warnings.reduce((total, warning) => total + warning.deduction, 0),
  )
  const { status, risk } = statusFromScore(score)

  return {
    indicators: warnings.map((warning) => warning.label),
    recommendations: recommendationsByStatus[status],
    recommendation: recommendationsByStatus[status].join(' '),
    risk,
    score,
    status,
    summary:
      warnings.length > 0
        ? `Found ${warnings.length} URL warning sign${warnings.length === 1 ? '' : 's'}.`
        : 'No strong URL phishing indicators were found.',
    warningSigns: warnings.map((warning) => warning.label),
  }
}

export function scanMessage(input) {
  const text = input.trim()
  const links = extractLinks(text)
  const warnings = []

  addWarning(warnings, /urgent|immediate|act now|expires|suspended/i.test(text), 'Uses urgency or pressure words', 16)
  addWarning(warnings, /bank|payment|credit card|ssn|social security/i.test(text), 'Requests financial or identity information', 20)
  addWarning(warnings, /password|passcode|credentials|login|signin/i.test(text), 'Requests password or login information', 22)
  addWarning(warnings, /prize|lottery|winner|jackpot|claim reward|free gift/i.test(text), 'Uses prize or lottery scam wording', 16)
  addWarning(warnings, links.length > 0, 'Contains links that should be verified before opening', 10)
  addWarning(
    warnings,
    links.some((link) => scanUrl(link).status !== 'Safe'),
    'Contains a suspicious link',
    18,
  )
  addWarning(warnings, /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd/i.test(text), 'Contains a shortened link', 18)
  addWarning(warnings, /dear customer|dear user|valued customer/i.test(text), 'Uses a generic greeting', 6)
  addWarning(warnings, /click here|confirm now|restore access|avoid suspension/i.test(text), 'Uses a suspicious call to action', 12)

  const score = clampScore(
    100 - warnings.reduce((total, warning) => total + warning.deduction, 0),
  )
  const { status, risk } = statusFromScore(score)

  return {
    indicators: warnings.map((warning) => warning.label),
    recommendations: recommendationsByStatus[status],
    recommendation: recommendationsByStatus[status].join(' '),
    risk,
    score,
    status,
    summary:
      warnings.length > 0
        ? `Found ${warnings.length} message warning sign${warnings.length === 1 ? '' : 's'}.`
        : 'No strong message phishing indicators were found.',
    warningSigns: warnings.map((warning) => warning.label),
  }
}

const trustedConsumerDomains = ['gmail.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'yahoo.com']
const suspiciousMailDomains = ['mail-security.com', 'account-verify.com', 'support-alerts.com']

const getEmailDomain = (sender) => {
  const match = sender.trim().toLowerCase().match(/@([a-z0-9.-]+\.[a-z]{2,})/i)
  return match?.[1] ?? ''
}

export function scanSender(sender) {
  const value = sender.trim()
  const domain = getEmailDomain(value)
  const localPart = value.split('@')[0]?.toLowerCase() ?? ''
  const warnings = []
  const tld = domain.split('.').at(-1)

  addWarning(warnings, !domain, 'Sender address is missing a valid domain', 24)
  addWarning(warnings, suspiciousTlds.includes(tld), `Sender uses suspicious .${tld} domain`, 18)
  addWarning(warnings, suspiciousMailDomains.some((item) => domain.includes(item)), 'Sender domain uses security-themed wording', 16)
  addWarning(warnings, hasTyposquatting(domain), 'Sender domain may impersonate a trusted brand', 24)
  addWarning(
    warnings,
    trustedConsumerDomains.includes(domain) && /support|security|billing|admin|verify/.test(localPart),
    'Free email domain is used for an official-sounding sender',
    14,
  )
  addWarning(warnings, /paypaI|micros0ft|go0gle|arnazon|faceb00k/i.test(value), 'Sender contains lookalike brand spelling', 22)

  const score = clampScore(
    100 - warnings.reduce((total, warning) => total + warning.deduction, 0),
  )
  const { status, risk } = statusFromScore(score)

  return {
    domain: domain || 'Unknown',
    risk,
    score,
    status,
    warningSigns: warnings.map((warning) => warning.label),
  }
}

export function scanEmail({ sender = '', subject = '', body = '' }) {
  const content = `${subject}\n${body}`.trim()
  const senderAnalysis = scanSender(sender)
  const contentAnalysis = scanMessage(content)
  const links = extractLinks(content)
  const linkAnalyses = links.map((link) => ({ url: link, ...scanUrl(link) }))
  const worstLinkScore =
    linkAnalyses.length > 0
      ? Math.min(...linkAnalyses.map((analysis) => analysis.score))
      : 100
  const linkWarnings = linkAnalyses.flatMap((analysis) =>
    analysis.warningSigns.map((warning) => `${analysis.url}: ${warning}`),
  )
  const linkStatus = statusFromScore(worstLinkScore)
  const finalScore = clampScore(
    Math.round(senderAnalysis.score * 0.3 + contentAnalysis.score * 0.4 + worstLinkScore * 0.3),
  )
  const { status, risk } = statusFromScore(finalScore)
  const warningSigns = [
    ...senderAnalysis.warningSigns.map((warning) => `Sender: ${warning}`),
    ...contentAnalysis.warningSigns.map((warning) => `Content: ${warning}`),
    ...linkWarnings.map((warning) => `Link: ${warning}`),
  ]

  return {
    emailBreakdown: {
      content: {
        score: contentAnalysis.score,
        status: contentAnalysis.status,
        warningSigns: contentAnalysis.warningSigns,
      },
      links: {
        extracted: links,
        score: worstLinkScore,
        status: linkStatus.status,
        warningSigns: linkWarnings,
      },
      sender: senderAnalysis,
    },
    indicators: warningSigns,
    recommendations: recommendationsByStatus[status],
    recommendation: recommendationsByStatus[status].join(' '),
    risk,
    score: finalScore,
    status,
    summary:
      warningSigns.length > 0
        ? `Found ${warningSigns.length} email warning sign${warningSigns.length === 1 ? '' : 's'} across sender, content, and links.`
        : 'No strong sender, content, or link phishing indicators were found.',
    warningSigns,
  }
}

export function analyzeThreat(input, type = 'Message') {
  if (type === 'URL' || type === 'Domain') return scanUrl(input)
  if (type === 'Email') {
    const [sender = '', ...contentLines] = input.split('\n')
    const content = contentLines.join('\n')
    return scanEmail({ sender, body: content })
  }
  return scanMessage(input)
}

export const riskStyles = {
  low: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 ring-emerald-500/25',
  medium: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 ring-amber-500/25',
  high: 'bg-orange-500/15 text-orange-700 dark:text-orange-300 ring-orange-500/25',
  critical: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 ring-rose-500/25',
  Safe: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 ring-emerald-500/25',
  Suspicious: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 ring-amber-500/25',
  Dangerous: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 ring-rose-500/25',
  Blocked: 'bg-rose-600 text-white ring-rose-500/40',
}
