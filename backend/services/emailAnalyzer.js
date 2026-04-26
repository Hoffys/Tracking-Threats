import { addWarning, getRiskFromScore, recommendationsFor, scoreWarnings } from './riskScorer.js'
import { extractLinks, scanMessage } from './messageScanner.js'
import { scanUrl } from './urlScanner.js'

const suspiciousTlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top']
const trustedFreeDomains = ['gmail.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'yahoo.com']

const getSenderDomain = (sender) => {
  const match = sender.trim().toLowerCase().match(/@([a-z0-9.-]+\.[a-z]{2,})/i)
  return match?.[1] ?? ''
}

function scanSender(sender) {
  const domain = getSenderDomain(sender)
  const localPart = sender.split('@')[0]?.toLowerCase() ?? ''
  const tld = domain.split('.').at(-1)
  const warnings = []

  addWarning(warnings, !domain, 'Sender address is missing a valid domain', 24)
  addWarning(warnings, suspiciousTlds.includes(tld), `Sender uses suspicious .${tld} domain`, 18)
  addWarning(warnings, /paypaI|micros0ft|go0gle|arnazon|faceb00k/i.test(sender), 'Sender contains lookalike brand spelling', 22)
  addWarning(
    warnings,
    trustedFreeDomains.includes(domain) && /support|security|billing|admin|verify/.test(localPart),
    'Free email domain is used for an official-sounding sender',
    14,
  )

  const score = scoreWarnings(warnings)
  return { ...getRiskFromScore(score), domain: domain || 'Unknown', score, warningSigns: warnings.map((warning) => warning.label) }
}

export function analyzeEmail({ sender = '', subject = '', body = '' }) {
  const content = `${subject}\n${body}`.trim()
  const senderRisk = scanSender(sender)
  const contentRisk = scanMessage(content)
  const links = extractLinks(content)
  const linkScans = links.map((link) => ({ url: link, ...scanUrl(link) }))
  const linkScore = linkScans.length > 0 ? Math.min(...linkScans.map((scan) => scan.score)) : 100
  const linkStatus = getRiskFromScore(linkScore)
  const score = Math.round(senderRisk.score * 0.3 + contentRisk.score * 0.4 + linkScore * 0.3)
  const risk = getRiskFromScore(score)
  const recommendations = recommendationsFor(risk.status)
  const warningSigns = [
    ...senderRisk.warningSigns.map((warning) => `Sender: ${warning}`),
    ...contentRisk.warningSigns.map((warning) => `Content: ${warning}`),
    ...linkScans.flatMap((scan) =>
      scan.warningSigns.map((warning) => `Link: ${scan.url}: ${warning}`),
    ),
  ]

  return {
    ...risk,
    score,
    summary:
      warningSigns.length > 0
        ? `Found ${warningSigns.length} email warning sign${warningSigns.length === 1 ? '' : 's'} across sender, content, and links.`
        : 'No strong sender, content, or link phishing indicators were found.',
    warningSigns,
    recommendations,
    recommendation: recommendations.join(' '),
    details: {
      emailBreakdown: {
        sender: senderRisk,
        content: {
          score: contentRisk.score,
          status: contentRisk.status,
          warningSigns: contentRisk.warningSigns,
        },
        links: {
          extracted: links,
          score: linkScore,
          status: linkStatus.status,
          warningSigns: linkScans.flatMap((scan) =>
            scan.warningSigns.map((warning) => `${scan.url}: ${warning}`),
          ),
        },
      },
    },
  }
}
