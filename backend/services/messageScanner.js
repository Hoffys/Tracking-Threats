import { scanUrl, MAX_URL_LENGTH, MAX_TEXT_LENGTH, MAX_LINKS, finding, localCoverage, localResult, contentCategories } from './urlScanner.js'

function collectLinks(text, maxLinks = Infinity) {
  const links = []
  const seen = new Set()
  let limited = false
  // Tokenization keeps matching bounded even for long dot/hyphen runs.
  for (const match of String(text ?? '').slice(0, MAX_TEXT_LENGTH).matchAll(/[^\s<>"']+/g)) {
    let token = match[0].replace(/^[([{]+/, '').replace(/[.,!?;:]+$/, '')
    if (token.length > MAX_URL_LENGTH) { limited = true; continue }
    const balances = { ')': 0, ']': 0, '}': 0 }
    const pairs = { '(': ')', '[': ']', '{': '}' }
    for (const character of token) {
      if (pairs[character]) balances[pairs[character]]++
      else if (Object.hasOwn(balances, character)) balances[character]--
    }
    while (/[)\]}]$/.test(token)) {
      const close = token.at(-1)
      if (balances[close] >= 0) break
      balances[close]++
      token = token.slice(0, -1)
    }
    token = token.replace(/[.,!?;:]+$/, '')
    const explicit = /^https?:\/\//i.test(token)
    // Email addresses, including www-prefixed domains and mailto:, are not URLs.
    if (!explicit && (token.split('/')[0].includes('@') || /^mailto:/i.test(token))) continue
    if (!explicit && !/^(?:[a-z0-9](?:[a-z0-9-]{0,62})\.)+[a-z]{2,63}(?::\d{1,5})?(?:[/?#]|$)/i.test(token)) continue
    let key
    try { key = new URL(explicit ? token : `https://${token}`).href } catch { continue }
    if (seen.has(key)) continue
    if (links.length === maxLinks) { limited = true; break }
    seen.add(key)
    links.push(token)
  }
  return { links, limited }
}

export const extractLinks = (text) => collectLinks(text).links

const secrets = '(?:password|passcode|credentials|otp|one[ -]time (?:password|code|pin)|verification code|security code|pin|recovery phrase|seed phrase)'
const request = '(?:send|share|provide|give|tell|reply|submit|disclose|forward|ibigay|ibahagi|isend|i-send|ipadala|paki-send|pakisend|pakibigay|sabihin)'
const directSecret = new RegExp(`\\b${request}\\b[^.!?;\\n]{0,65}\\b${secrets}\\b|\\b${secrets}\\b[^.!?;\\n]{0,35}\\b(?:ipadala|ibigay|isend|i-send|pakisend|pakibigay)\\b`, 'gi')
const educationalPrefix = /(?:\b(?:never|not|don't|dont|avoid|refuse|huwag|wag|hindi|no one|nobody)\b|\b(?:scammers?|fraudsters?|phishers?)\b|\b(?:example|warning|beware|red flags?|suspicious requests?)\b)/i

function activeRequest(clause, pattern) {
  pattern.lastIndex = 0
  for (const match of clause.matchAll(pattern)) {
    const prefix = clause.slice(Math.max(0, match.index - 100), match.index)
    if (!educationalPrefix.test(prefix) && !/\b(?:never|not|don't|huwag|wag|hindi)\b/i.test(match[0])) return match[0]
  }
  return null
}

export function scanMessage(content) {
  const raw = String(content ?? '')
  const text = raw.slice(0, MAX_TEXT_LENGTH).trim()
  const { links, limited } = collectLinks(text, MAX_LINKS)
  const linkAnalyses = links.map((url) => ({ url, ...scanUrl(url) }))
  const findings = []
  // Negation/education applies to its clause, never to the entire message.
  const clauses = text.split(/\n|[!?;]|\.(?=\s)|\b(?:but|however|pero)\b/i).map((clause) => clause.trim())
  const secretRequest = clauses.map((clause) => activeRequest(clause, directSecret)).find(Boolean)
  if (secretRequest) findings.push(finding('secret-request', 'Directly asks the recipient to disclose a secret', 55, { phrase: secretRequest }))
  const entryPattern = new RegExp(`\\b(?:enter|type|confirm|ilagay|isulat)\\b[^.!?;\\n]{0,65}\\b${secrets}\\b`, 'gi')
  const entryRequest = clauses.map((clause) => activeRequest(clause, entryPattern)).find(Boolean)
  if (entryRequest && !secretRequest) findings.push(finding('secret-entry', 'Asks for secret entry; verify the destination before proceeding', 12, { phrase: entryRequest }))
  const financialPattern = /\b(?:send|share|provide|give|reply|submit|ibigay|ipadala)\b[^.!?;\n]{0,65}\b(?:credit card (?:number|details)|bank (?:details|account number)|social security number|ssn)\b/gi
  const financialRequest = clauses.map((clause) => activeRequest(clause, financialPattern)).find(Boolean)
  if (financialRequest) findings.push(finding('financial-request', 'Asks the recipient to disclose financial or identity details', 30, { phrase: financialRequest }))
  const accountPattern = /\b(?:verify|update|confirm|unlock|restore|validate)\b[^.!?;\n]{0,45}\b(?:account|identity|billing|payment)\b/gi
  const accountRequest = links.length && clauses.map((clause) => activeRequest(clause, accountPattern)).find(Boolean)
  if (accountRequest) findings.push(finding('account-request-link', 'Account or identity action is requested alongside a link', 12, { phrase: accountRequest }))
  const feePattern = /\b(?:pay|send|deposit|transfer)\b[^.!?;\n]{0,65}\b(?:fee|money|payment)\b[^.!?;\n]{0,65}\b(?:prize|winnings|lottery|reward)\b/gi
  const feeRequest = clauses.map((clause) => activeRequest(clause, feePattern)).find(Boolean)
  if (feeRequest) findings.push(finding('advance-fee', 'Requests payment to obtain a prize or reward', 50, { phrase: feeRequest }))
  const concerningLink = linkAnalyses.some((link) => link.score < 80)
  const requestContext = findings.length > 0 || concerningLink
  if (requestContext && /\b(?:urgent|immediately|act now|within \d+ (?:minutes?|hours?)|now|ngayon|agad)\b/i.test(text)) {
    findings.push(finding('request-pressure', 'Urgency accompanies a sensitive request or concerning link', 12, { context: 'urgent request' }))
  }
  if (requestContext && /\b(?:account (?:will be |is )?(?:suspended|closed|locked)|lose access|permanently disabled|isu-suspend|masususpend|maba-block)\b/i.test(text)) {
    findings.push(finding('account-threat', 'Threatens account loss alongside a sensitive request or concerning link', 15, { context: 'account loss threat' }))
  }
  const contentScore = Math.max(0, 100 - findings.reduce((sum, item) => sum + item.deduction, 0))
  const linkScore = Math.min(100, ...linkAnalyses.map((link) => link.score))
  const score = Math.min(contentScore, linkScore)
  // Preserve link evidence without deducting it again from the content score.
  for (const link of linkAnalyses) {
    findings.push(...link.details.findings.map((item) => ({ ...item, source: 'link', evidence: { ...item.evidence, url: link.url } })))
  }
  const limitations = ['Message intent and sender identity were not verified.', 'Linked pages were not fetched.']
  if (raw.length > MAX_TEXT_LENGTH) limitations.push(`Only the first ${MAX_TEXT_LENGTH} message characters were checked.`)
  if (limited) limitations.push(`Link analysis is limited to ${MAX_LINKS} unique URLs of at most ${MAX_URL_LENGTH} characters; some links were not checked.`)
  const categoryWarnings = [...contentCategories(text), ...linkAnalyses.flatMap((link) => link.details.categoryWarnings)]
    .filter((item, index, all) => all.findIndex((other) => other.category === item.category) === index)
  return localResult(findings, { links, linkAnalyses, contentScore, coverage: localCoverage(limitations), categoryWarnings }, 'message', score)
}
