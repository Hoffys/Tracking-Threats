import { getRiskFromScore } from './riskScorer.js'
import { scanMessage } from './messageScanner.js'
import { scanUrl, officialDomains, MAX_TEXT_LENGTH, finding, localCoverage, localResult } from './urlScanner.js'

function scanSender(sender, sensitiveContext) {
  const text = String(sender ?? '').slice(0, 1024).trim()
  const match = text.match(/(?:^|[<\s])([a-z0-9.!#$%&'*+/=?^_`{|}~-]+)@([a-z0-9.-]+\.[a-z]{2,63})(?=>|\s|$)/i)
  const domain = match?.[2]?.toLowerCase() ?? ''
  const findings = []
  // Missing metadata is a coverage limitation, not evidence of malicious content.
  if (text && !domain) findings.push(finding('invalid-sender', 'Supplied sender address could not be interpreted', 10, { context: 'sender format' }))
  const domainRisk = domain ? scanUrl(`https://${domain}`) : null
  if (domainRisk) findings.push(...domainRisk.details.findings)
  if (domain && sensitiveContext) {
    const claimed = `${text.split('<')[0]} ${match[1]}`.toLowerCase().split(/[^a-z0-9]+/)
    for (const [brand, owners] of Object.entries(officialDomains)) {
      if (claimed.includes(brand) && !owners.includes(domainRisk.details.registrableDomain)) {
        findings.push(finding('sender-brand-claim', `Sender claims ${brand} while requesting sensitive action from an unrelated domain`, 25, { brand, domain }))
        break
      }
    }
  }
  return localResult(findings, { domain: domain || 'Unknown', coverage: localCoverage([
    'Sender authentication (SPF, DKIM, DMARC) was not checked.',
    ...(!text ? ['Sender address was not supplied.'] : []),
    ...(String(sender ?? '').length > 1024 ? ['Only the first 1024 sender characters were checked.'] : []),
  ]) }, 'sender')
}

export function analyzeEmail({ sender = '', subject = '', body = '' } = {}) {
  const subjectText = String(subject ?? '')
  const bodyText = String(body ?? '')
  const content = `${subjectText.slice(0, MAX_TEXT_LENGTH)}\n${bodyText.slice(0, MAX_TEXT_LENGTH)}`
  const contentRisk = scanMessage(content)
  const senderRisk = scanSender(sender, contentRisk.details.findings.some((item) => item.deduction > 0))
  const linkScans = contentRisk.details.linkAnalyses
  const linkScore = Math.min(100, ...linkScans.map((scan) => scan.score))
  const score = Math.min(senderRisk.score, contentRisk.score, linkScore)
  const findings = [
    ...senderRisk.details.findings.map((item) => ({ ...item, source: 'sender', label: `Sender: ${item.label}` })),
    ...contentRisk.details.findings.map((item) => ({ ...item, source: item.source ?? 'content', label: `Content: ${item.label}` })),
  ]
  const limitations = [...senderRisk.details.coverage.limitations, ...contentRisk.details.coverage.limitations]
  if (subjectText.length + bodyText.length + 1 > MAX_TEXT_LENGTH) limitations.push(`Only the first ${MAX_TEXT_LENGTH} combined subject/body characters were checked.`)
  return localResult(findings, {
    coverage: localCoverage([...new Set(limitations)].filter((item) => !localCoverage().limitations.includes(item))),
    categoryWarnings: contentRisk.details.categoryWarnings,
    emailBreakdown: {
      sender: { ...senderRisk, domain: senderRisk.details.domain },
      content: { score: contentRisk.score, status: contentRisk.status, warningSigns: contentRisk.warningSigns },
      links: {
        extracted: contentRisk.details.links, score: linkScore, status: getRiskFromScore(linkScore).status,
        warningSigns: linkScans.flatMap((scan) => scan.warningSigns.map((warning) => `${scan.url}: ${warning}`)),
      },
    },
  }, 'email', score)
}
