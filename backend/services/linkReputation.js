import { extractLinks } from './messageScanner.js'
import { scanUrl, MAX_TEXT_LENGTH } from './urlScanner.js'
import { enrichUrlAnalysis } from './threatIntel.js'
import { getRiskFromScore, recommendationsFor } from './riskScorer.js'
import { localCoverage, providerCoverage } from './coverage.js'

export const maxReputationLinks = 5

export async function enrichContentLinks(content, baseAnalysis, lookup = enrichUrlAnalysis) {
  const links = [...new Set(extractLinks(content).map((link) => {
    try { return new URL(link.includes('://') ? link : `https://${link}`).href } catch { return null }
  }).filter(Boolean))]
  if (links.length === 0) {
    return { ...baseAnalysis, details: { ...baseAnalysis.details,
      coverage: {
        ...localCoverage('Local text and sender rules only; no links were present for reputation checks. Sender authenticity was not verified.'),
        limitations: [...(baseAnalysis.details?.coverage?.limitations ?? []), 'No extracted links were available for reputation checks.'],
      },
    } }
  }

  const selected = links.slice(0, maxReputationLinks)
  const analyses = []
  // At most two links in flight, with a fixed per-submission cap.
  for (let index = 0; index < selected.length; index += 2) {
    analyses.push(...await Promise.all(selected.slice(index, index + 2).map(async (url) => {
      const local = scanUrl(url)
      try { return await lookup(url, local) } catch {
        return { ...local, details: { ...local.details, threatIntel: [{
          provider: 'Link reputation', checked: false, error: 'Link reputation lookup failed',
        }] } }
      }
    })))
  }

  const providers = analyses.flatMap((analysis) => analysis.details?.threatIntel ?? [])
  const coverage = providerCoverage(providers, [
    ...(baseAnalysis.details?.coverage?.limitations ?? []).filter((item) => item !== 'Reputation not checked.'),
    'Links were checked using URL rules and reputation; message authenticity and linked page content were not verified.',
    ...(links.length > selected.length ? [`Only the first ${maxReputationLinks} unique links were checked for reputation.`] : []),
  ])
  if ((selected.length < links.length || content.length > MAX_TEXT_LENGTH) && coverage.status === 'complete') coverage.status = 'partial'
  const score = Math.min(baseAnalysis.score, ...analyses.map((analysis) => analysis.score))
  const risk = getRiskFromScore(score)
  const recommendations = recommendationsFor(risk.status)
  const warningSigns = [...new Set([
    ...baseAnalysis.warningSigns,
    ...providers.filter((result) => result.checked && !result.error && !result.skipped && result.warning)
      .map((result) => `Embedded link: ${result.warning}`),
  ])]
  return {
    ...baseAnalysis, ...risk, score, warningSigns, recommendations,
    recommendation: recommendations.join(' '),
    summary: `Found ${warningSigns.length} warning sign${warningSigns.length === 1 ? '' : 's'} after checking message content and links.`,
    details: {
      ...baseAnalysis.details,
      threatIntel: providers,
      coverage: { ...coverage, linksChecked: selected.length, totalLinks: links.length },
      categories: [...new Set([
        ...(baseAnalysis.details?.categories ?? []),
        ...analyses.flatMap((analysis) => analysis.details?.categories ?? []),
      ])],
      ...(baseAnalysis.details?.emailBreakdown ? {
        emailBreakdown: {
          ...baseAnalysis.details.emailBreakdown,
          links: { ...baseAnalysis.details.emailBreakdown.links,
            score: Math.min(...analyses.map((analysis) => analysis.score)),
            status: getRiskFromScore(Math.min(...analyses.map((analysis) => analysis.score))).status,
            warningSigns: [...new Set(analyses.flatMap((analysis) => analysis.warningSigns))],
          },
        },
      } : {}),
    },
  }
}
