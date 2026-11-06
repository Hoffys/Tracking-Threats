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
const sensitiveRequestAction = '(?:enter|type|provide|give|send|share|submit|upload|attach|take|photograph|scan|reply with|ask(?:s|ed)? for|request(?:s|ed)?)'
const paymentData = '(?:(?:(?:credit|debit|payment)\\s+card(?!(?:\\s+payment\\b))(?:\\s+(?:number|details?|information|info|data|photos?|pictures?|images?|copies|scans))?)|card\\s+(?:number|details?|information|info|data|photos?|pictures?|images?|copies|scans)|(?:front\\s*(?:and|&|/)\\s*back|both sides?)[^.!?;\\n]{0,45}\\b(?:payment|credit|debit)?\\s*card|payment\\s+(?:details?|information|info|data))'
const governmentId = "(?:passport(?:\\s+(?:photo|picture|image|copy|scan))?|driver['’]?s?\\s+licen[cs]e(?:\\s+(?:photo|picture|image|copy|scan))?|driving\\s+licen[cs]e(?:\\s+(?:photo|picture|image|copy|scan))?|government[- ]issued\\s+(?:id|identity document)|national\\s+id|identity document(?:\\s+(?:photo|picture|image|copy|scan))?|proof\\s+of\\s+identity|id\\s+(?:photo|picture|image|copy|scan))"
const sensitiveDataRequest = new RegExp(`\\b${sensitiveRequestAction}\\b[^.!?;\\n]{0,100}\\b(?:${paymentData}|${governmentId})\\b`, 'gi')

function withoutQuotedText(text) {
  let result = ''
  for (let index = 0; index < text.length;) {
    const open = text.charCodeAt(index)
    const close = open === 0x22 ? 0x22 : open === 0x201c ? 0x201d : open === 0x2018 ? 0x2019 : null
    if (close === null) {
      result += text[index++]
      continue
    }
    const end = text.indexOf(String.fromCharCode(close), index + 1)
    if (end < 0 || end - index > 1000 || /[\r\n]/.test(text.slice(index, end))) {
      result += text[index++]
      continue
    }
    result += ' '.repeat(end - index + 1)
    index = end + 1
  }
  return result
}

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
  const analysisText = withoutQuotedText(text)
  const { links, limited } = collectLinks(text, MAX_LINKS)
  const linkAnalyses = links.map((url) => ({ url, ...scanUrl(url) }))
  const findings = []
  // Negation/education applies to its clause, never to the entire message.
  const clauses = analysisText.split(/\n|[!?;]|\.(?=\s)|\b(?:but|however|pero)\b/i).map((clause) => clause.trim())
  const secretRequest = clauses.map((clause) => activeRequest(clause, directSecret)).find(Boolean)
  if (secretRequest) findings.push(finding('secret-request', 'Directly asks the recipient to disclose a secret', 55, { phrase: secretRequest }))
  const entryPattern = new RegExp(`\\b(?:enter|type|confirm|ilagay|isulat)\\b[^.!?;\\n]{0,65}\\b${secrets}\\b`, 'gi')
  const entryRequest = clauses.map((clause) => activeRequest(clause, entryPattern)).find(Boolean)
  if (entryRequest && !secretRequest) findings.push(finding('secret-entry', 'Asks for secret entry; verify the destination before proceeding', 12, { phrase: entryRequest }))
  const financialPattern = /\b(?:send|share|provide|give|reply|submit|ibigay|ipadala)\b[^.!?;\n]{0,65}\b(?:credit card (?:number|details)|bank (?:details|account number)|social security number|ssn)\b/gi
  const financialRequest = clauses.map((clause) => activeRequest(clause, financialPattern)).find(Boolean)
  const sensitiveMatch = clauses.map((clause, index) => ({ clause, index, phrase: activeRequest(clause, sensitiveDataRequest) })).find((item) => item.phrase)
  const sensitivePhrase = sensitiveMatch?.phrase
  const isPaymentCardPhoto = Boolean(sensitivePhrase && /(?:photo|picture|image|copy|scan|front|back|both sides)/i.test(sensitivePhrase) && /(?:card|both sides)/i.test(sensitivePhrase))
  const requestedData = sensitivePhrase
    ? /passport|licen[cs]e|government[- ]issued|national\s+id|identity document|proof of identity|\bid\s+(?:photo|picture|image)/i.test(sensitivePhrase)
      ? 'government identity document'
      : isPaymentCardPhoto ? 'payment-card photo or image' : 'payment-card or payment details'
    : null
  const sensitiveContextText = sensitiveMatch
    ? clauses.slice(Math.max(0, sensitiveMatch.index - 1), sensitiveMatch.index + 2).join(' ')
    : ''
  const analysisLinks = sensitiveContextText
    ? collectLinks(sensitiveContextText, MAX_LINKS).links.map((url) => ({ url, ...scanUrl(url) }))
    : []
  const hasLink = analysisLinks.length > 0
  const deceptiveLink = analysisLinks.some((link) => link.score < 80)
  const deliveryContext = /\b(?:parcel|package|shipment|delivery|redelivery|courier|customs)\b/i.test(sensitiveContextText)
  const employmentContext = /\b(?:job|employment|employer|recruitment|salary|onboarding|remote role|hired)\b/i.test(sensitiveContextText)
  const prizeContext = /\b(?:prize|reward|winner|winnings|lottery|jackpot)\b/i.test(sensitiveContextText)
  const accountContext = /\b(?:account|verify|verification|unlock|restore|recovery|billing)\b/i.test(sensitiveContextText)
  const coerciveContext = /\b(?:urgent|immediately|act now|right away|within \d+ (?:minutes?|hours?)|will be returned|returned to sender|held until|lose access|will be suspended|unless you)\b/i.test(sensitiveContextText)
  const unofficialContext = /\b(?:unofficial|unfamiliar|untrusted|unknown)\s+(?:link|site|website|portal|app)\b|\boutside (?:the|our) (?:official )?app\b|\bvia (?:whatsapp|sms|text|email|messaging app)\b/i.test(sensitiveContextText)
  const unfamiliarLink = unofficialContext || deceptiveLink
  const paymentRequest = requestedData?.startsWith('payment-') ?? false
  const contextualSensitiveRequest = Boolean(sensitivePhrase && (
    deceptiveLink || unofficialContext ||
    (requestedData === 'government identity document' && (coerciveContext || (deliveryContext && hasLink))) ||
    (paymentRequest && (
      coerciveContext ||
      (deliveryContext && hasLink && (unfamiliarLink || isPaymentCardPhoto)) ||
      (employmentContext && isPaymentCardPhoto) ||
      prizeContext ||
      (accountContext && hasLink && unfamiliarLink)
    ))
  ))
  const sensitiveContexts = []
  if (deceptiveLink) sensitiveContexts.push('deceptive submission link')
  if (unofficialContext) sensitiveContexts.push('unofficial or unfamiliar submission channel')
  if (deliveryContext && hasLink) sensitiveContexts.push('parcel or delivery payment context')
  if (employmentContext && isPaymentCardPhoto) sensitiveContexts.push('employment lure with an excessive card-photo request')
  if (prizeContext && paymentRequest) sensitiveContexts.push('prize or reward claim')
  if (accountContext && hasLink && paymentRequest) sensitiveContexts.push('account-verification lure with a payment-data link')
  if (coerciveContext) sensitiveContexts.push('coercive urgency or threat')

  if (sensitivePhrase) {
    const evidence = { requestedData, requestPhrase: sensitivePhrase.slice(0, 160), contexts: sensitiveContexts,
      linkedHosts: analysisLinks.map((link) => link.details.domain).slice(0, 5) }
    if (financialRequest) {
      findings.push(finding('financial-request', contextualSensitiveRequest
        ? `Requests financial details with ${sensitiveContexts.join(' and ')}`
        : 'Requests financial details without additional suspicious context', 30, { ...evidence, phrase: financialRequest }))
      if (contextualSensitiveRequest) findings.push(finding('contextual-sensitive-data-request', 'Sensitive-data request has additional suspicious context', 0, evidence))
    } else if (contextualSensitiveRequest) {
      const requested = requestedData === 'government identity document' ? 'government identity-document details' : requestedData
      findings.push(finding('sensitive-data-request', `Requests ${requested}`, 12, evidence))
      findings.push(finding('sensitive-data-context', `Sensitive-data request has ${sensitiveContexts.join(' and ')}`, 12, evidence))
    } else {
      findings.push(finding('sensitive-data-request', `Requests ${requestedData}; no additional suspicious context was established`, 0, evidence))
    }
  } else if (financialRequest) {
    findings.push(finding('financial-request', 'Asks the recipient to disclose financial or identity details', 30, { phrase: financialRequest }))
  }
  const accountPattern = /\b(?:verify|update|confirm|unlock|restore|validate)\b[^.!?;\n]{0,45}\b(?:account|identity|billing|payment)\b/gi
  const accountRequest = links.length && clauses.map((clause) => activeRequest(clause, accountPattern)).find(Boolean)
  if (accountRequest && !contextualSensitiveRequest) findings.push(finding('account-request-link', 'Account or identity action is requested alongside a link', 12, { phrase: accountRequest }))
  const feePattern = /\b(?:pay|send|deposit|transfer)\b[^.!?;\n]{0,65}\b(?:fee|money|payment)\b[^.!?;\n]{0,65}\b(?:prize|winnings|lottery|reward)\b/gi
  const feeRequest = clauses.map((clause) => activeRequest(clause, feePattern)).find(Boolean)
  if (feeRequest) findings.push(finding('advance-fee', 'Requests payment to obtain a prize or reward', 50, { phrase: feeRequest }))
  const concerningLink = linkAnalyses.some((link) => link.score < 80)
  const requestContext = findings.some((item) => item.deduction > 0) || concerningLink
  const contextualScoreIncludesPressure = findings.some((item) => item.code === 'sensitive-data-context' && item.deduction > 0)
  if (requestContext && !contextualScoreIncludesPressure && /\b(?:urgent|immediately|act now|within \d+ (?:minutes?|hours?)|now|ngayon|agad)\b/i.test(analysisText)) {
    findings.push(finding('request-pressure', 'Urgency accompanies a sensitive request or concerning link', 12, { context: 'urgent request' }))
  }
  if (requestContext && !contextualScoreIncludesPressure && /\b(?:account (?:will be |is )?(?:suspended|closed|locked)|lose access|permanently disabled|isu-suspend|masususpend|maba-block)\b/i.test(analysisText)) {
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
  const result = localResult(findings, { links, linkAnalyses, contentScore, coverage: localCoverage(limitations), categoryWarnings }, 'message', score)
  if (findings.some((item) => item.code === 'sensitive-data-request' || item.code === 'financial-request' && item.deduction === 0)) {
    result.summary = 'A sensitive-data request was noted, but no additional suspicious context was established. Reputation was not checked.'
  }
  return result
}
