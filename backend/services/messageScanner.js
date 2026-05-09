import { addWarning, getRiskFromScore, recommendationsFor, scoreWarnings } from './riskScorer.js'
import { scanUrl } from './urlScanner.js'

export const extractLinks = (text) =>
  text.match(
    /https?:\/\/[^\s<>"']+|www\.[^\s<>"']+|(?:[a-z0-9-]+\.)+[a-z]{2,24}(?:\/[^\s<>"']*)?/gi,
  ) ?? []

export function scanMessage(content) {
  const text = content.trim()
  const links = extractLinks(text)
  const linkAnalyses = links.map((link) => scanUrl(link))
  const warnings = []

  addWarning(warnings, /urgent|immediate|act now|expires|suspended/i.test(text), 'Uses urgency or pressure words', 16)
  addWarning(warnings, /bank|payment|credit card|ssn|social security/i.test(text), 'Requests financial or identity information', 20)
  addWarning(warnings, /password|passcode|credentials|login|signin/i.test(text), 'Requests password or login information', 22)
  addWarning(warnings, /prize|lottery|winner|jackpot|claim reward|free gift/i.test(text), 'Uses prize or lottery scam wording', 16)
  addWarning(warnings, /\b\d{10,11}\b/.test(text), 'Contains a phone-number style account or sender reference', 10)
  addWarning(
    warnings,
    /\b(withdraw|laruin|lucky|binggo|bingo|galing kay|maari mo na|maaari mo na|ngayon|jackpot|casino|bet|betting|slots|sabong|scatter|bonus|deposit|freebet)\b/i.test(text),
    'Uses cash-out, gambling, or reward wording common in SMS scams',
    18,
  )
  addWarning(warnings, /sender\s*:/i.test(text), 'Message includes copied sender metadata', 4)
  addWarning(warnings, links.length > 0, 'Contains links that should be verified before opening', 10)
  addWarning(
    warnings,
    linkAnalyses.some((analysis) => analysis.status === 'Dangerous'),
    'Contains a dangerous link',
    45,
  )
  addWarning(
    warnings,
    linkAnalyses.some((analysis) => analysis.status === 'Suspicious'),
    'Contains a suspicious link',
    18,
  )

  const score = scoreWarnings(warnings)
  const risk = getRiskFromScore(score)
  const recommendations = recommendationsFor(risk.status)

  return {
    ...risk,
    score,
    summary:
      warnings.length > 0
        ? `Found ${warnings.length} message warning sign${warnings.length === 1 ? '' : 's'}.`
        : 'No strong message phishing indicators were found.',
    warningSigns: warnings.map((warning) => warning.label),
    recommendations,
    recommendation: recommendations.join(' '),
    details: { links },
  }
}
