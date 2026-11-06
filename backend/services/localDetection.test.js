import assert from 'node:assert/strict'
import test from 'node:test'
import { scanUrl, MAX_LINKS, MAX_TEXT_LENGTH, MAX_URL_LENGTH, piracySiteIndicators } from './urlScanner.js'
import { scanMessage, extractLinks } from './messageScanner.js'
import { analyzeEmail } from './emailAnalyzer.js'
import { attachThreatClassification } from './threatClassification.js'
import { combineUrlReputation } from './threatIntel.js'

test('ordinary login, support, generic words, HTTP and suffixes do not block', () => {
  for (const url of [
    'https://example.com/login', 'http://support.example.xyz/account/login',
    'https://bank.example.co.uk/support', 'https://support-tools-123.info/login',
    'https://apply.org/', 'https://bad.com/', 'https://my-movie-stream.example/',
  ]) {
    assert.equal(scanUrl(url).status, 'Safe', url)
  }
})

test('PSL ownership recognizes official subdomains and multilevel suffixes', () => {
  for (const [url, domain] of [
    ['https://online.bdo.com.ph/login', 'bdo.com.ph'],
    ['https://online.bpi.com.ph/verify', 'bpi.com.ph'],
    ['https://accounts.google.co.uk/login', 'google.co.uk'],
    ['https://login.microsoftonline.com/', 'microsoftonline.com'],
    ['https://help.example.co.uk/support', 'example.co.uk'],
    ['https://accounts.paypal.com./login', 'paypal.com'],
  ]) {
    const result = scanUrl(url)
    assert.equal(result.status, 'Safe', url)
    assert.equal(result.details.registrableDomain, domain)
  }
})

test('brand domain, subdomain and private-hosting tricks require ownership', () => {
  for (const url of [
    'https://paypal.example.net/login', 'https://paypal.com.example.net/verify',
    'https://paypal-login.example/login', 'https://paypal.xyz/login',
    'https://microsoft.github.io/login', 'https://google.blogspot.com/verify',
    'https://bdo.com.ph.example.net/login',
  ]) {
    const result = scanUrl(url)
    assert.equal(result.status, 'Dangerous', url)
    assert(result.details.findings.some((item) => item.code === 'brand-impersonation'))
  }
  assert.equal(scanUrl('https://myproject.github.io/login').status, 'Safe')
})

test('brand names in query parameters remain informational without corroborating URL evidence', () => {
  for (const url of [
    'https://shop.example/search?brand=shopee',
    'https://shopee.ph/?brand=shopee',
    'https://example.com/campaign?brand=paypal',
    'https://paypal.com/login?brand=paypal',
    'https://example.com/campaign?source=spring&brand=paypal&medium=email',
    'https://example.com/login?utm_campaign=paypal',
    'https://example.com/login?redirect=paypal',
    'https://example.com/campaign?redirect=paypal',
    'https://example.com/login?brand=shopee',
    'https://example.com/search?brand=shopee',
    'https://example.com/login?brand=paypal&brand=shopee',
    'https://paypol.example/campaign?brand=paypal&next=login',
    'https://example.com/campaign?redirect=%50ayPal',
    'https://example.com/campaign?redirect=%ZZpaypal',
    'https://example.com/campaign?campaign=paypal%ZZ',
    'https://example.com/login',
  ]) {
    const result = scanUrl(url)
    assert.equal(result.status, 'Safe', url)
    assert.equal(result.score, 100, url)
    assert.ok(!result.details.findings.some((item) => item.code === 'brand-query-impersonation'), url)
  }

  const diagnostic = scanUrl('https://example.com/campaign?brand=paypal')
  assert.ok(diagnostic.details.findings.some((item) => item.code === 'query-brand-mention' && item.deduction === 0))
  assert.equal(diagnostic.score, 100)
  assert.deepEqual(diagnostic.warningSigns, [])
  assert.match(diagnostic.summary, /^No strong local URL phishing indicators/)
  assert.deepEqual(diagnostic.details.categories, [])
  assert.ok(diagnostic.details.findings.some((item) => item.code === 'query-brand-mention'))
  const combined = combineUrlReputation(diagnostic, [])
  assert.equal(combined.score, 100)
  assert.deepEqual(combined.warningSigns, [])
  assert.ok(combined.summary.startsWith('No strong local URL phishing indicators'))
  assert.ok(combined.details.findings.some((item) => item.code === 'query-brand-mention'))
  const classification = attachThreatClassification('URL', diagnostic).details.threatClassification
  assert.equal(classification.threatName, 'No threat identified')
  assert.equal(classification.confidence, 'No threat detected')
  assert.ok(!classification.whyDetected.some((item) => /paypal|query/i.test(item)))
})

test('brand query findings need independent host or URL-structure evidence', () => {
  for (const url of [
    'https://unrelated.example/login?brand=paypal',
    'https://unrelated.example/account/verify?source=mail&BRAND=%50aYPal',
    'https://unrelated.example/account/recovery?brand=shopee&brand=paypal&brand=paypal',
  ]) {
    const result = scanUrl(url)
    assert.equal(result.score, 100, url)
    assert.equal(result.status, 'Safe', url)
    assert.ok(result.details.findings.some((item) => item.code === 'query-brand-mention' && item.deduction === 0), url)
    assert.ok(!result.details.findings.some((item) => item.code === 'brand-query-impersonation'), url)
  }

  const independentCases = [
    ['https://192.0.2.1/campaign?brand=paypal', 65, 'Suspicious', 'Low', 'Suspicious URL with a brand reference'],
    ['https://person@unrelated.example/campaign?brand=paypal', 45, 'Dangerous', 'Medium', 'Suspected credential phishing page'],
    ['https://paypa1.example/campaign?brand=shopee', 45, 'Dangerous', 'Medium', 'Suspected credential phishing page'],
  ]
  for (const [url, score, status, confidence, threatName] of independentCases) {
    const result = scanUrl(url)
    assert.equal(result.score, score, url)
    assert.equal(result.status, status, url)
    const finding = result.details.findings.find((item) => item.code === 'brand-query-impersonation')
    assert.equal(finding?.deduction, 25, url)
    assert.ok(finding.evidence.corroboration.length > 0, url)
    const classification = attachThreatClassification('URL', result).details.threatClassification
    assert.equal(classification.confidence, confidence, url)
    assert.equal(classification.threatName, threatName, url)
  }

  const repeated = scanUrl('https://person@unrelated.example/campaign?src=mail&brand=shopee&brand=paypal&brand=paypal')
  const queryFinding = repeated.details.findings.find((item) => item.code === 'brand-query-impersonation')
  assert.deepEqual(queryFinding.evidence.brands, ['shopee', 'paypal'])
  assert.equal(repeated.details.findings.filter((item) => item.code === 'brand-query-impersonation').length, 1)

  const userinfo = scanUrl('https://paypal.com@unrelated.example/?brand=paypal')
  assert.ok(userinfo.details.findings.some((item) => item.code === 'url-userinfo'))
  assert.ok(!userinfo.details.findings.some((item) => item.code === 'brand-query-impersonation'))
})

test('query brand evidence is not counted again when hostname impersonation already matches it', () => {
  for (const url of [
    'https://paypal-login.example/login?brand=paypal',
    'https://paypal-facebook-login.example/login?brand=paypal',
  ]) {
    const result = scanUrl(url)
    assert.equal(result.status, 'Dangerous')
    assert.ok(result.details.findings.some((item) => item.code === 'brand-impersonation'))
    assert.ok(!result.details.findings.some((item) => item.code === 'brand-query-impersonation'))
    assert.ok(result.details.findings.some((item) => item.code === 'query-brand-mention' && item.deduction === 0))
  }
})

test('query brand parsing respects its parameter and value bounds', () => {
  const tooManyParameters = `https://unrelated.example/login?${Array.from({ length: 32 }, (_, index) => `p${index}=x`).join('&')}&brand=paypal`
  const longValue = `https://unrelated.example/login?campaign=${'x'.repeat(256)}paypal`
  for (const url of [tooManyParameters, longValue]) {
    const result = scanUrl(url)
    assert.equal(result.status, 'Safe', url)
    assert.ok(!result.details.findings.some((item) => item.code.startsWith('query-brand-') || item.code === 'brand-query-impersonation'), url)
  }
})

test('bounded lookalikes use long brands, substitutions and credential context', () => {
  for (const url of ['https://paypa1.com/login', 'https://paypol.com/login', 'https://micros0ft.example/verify']) {
    assert.equal(scanUrl(url).status, 'Dangerous', url)
  }
  assert.equal(scanUrl('https://paypol.com/').status, 'Safe')
  assert.equal(scanUrl('https://bdp.com/login').status, 'Safe')
  assert.equal(scanUrl('https://myappleorchard.com/').status, 'Safe')
})

test('official ownership never bypasses unrelated destination evidence', () => {
  assert.equal(scanUrl('https://paypal.com@google.com/login').status, 'Dangerous')
  const result = scanUrl('https://google.com@unrelated.example/')
  assert.equal(result.status, 'Dangerous')
  assert.equal(result.details.domain, 'unrelated.example')
  assert(result.details.findings.some((item) => item.code === 'deceptive-userinfo'))
})

test('internationalized domains need context and homographs retain evidence', () => {
  assert.equal(scanUrl('https://bücher.de/').score, 100)
  assert.equal(scanUrl('https://bücher.de/login').status, 'Safe')
  assert.equal(scanUrl('https://раypal.com/login').status, 'Dangerous')
})

test('gambling and piracy are separate categories with no phishing deductions', () => {
  for (const result of [
    scanUrl('https://casino.example/torrent'),
    scanMessage('A discussion of casino gambling, pirated software and torrents.'),
    analyzeEmail({ body: 'A discussion of casino gambling, pirated software and torrents.' }),
  ]) {
    assert.equal(result.score, 100)
    assert.deepEqual(result.details.categories.sort(), ['gambling-content', 'piracy-content'])
    assert.equal(result.details.categoryWarnings.length, 2)
    assert.deepEqual(result.warningSigns, [])
    assert.match(result.recommendations[0], /Download risk is unknown/)
  }
  const mixed = scanUrl('https://paypal.example/login/casino/torrent')
  assert.equal(mixed.status, 'Dangerous')
  assert(mixed.details.categories.includes('phishing-indicators'))
})

test('piracy warnings cover named torrent, repack and cracked-software sources', () => {
  for (const indicator of piracySiteIndicators) {
    const result = scanUrl(`https://example.com/download/${indicator}`)
    assert.equal(result.status, 'Safe', indicator)
    assert(result.details.categories.includes('piracy-content'), indicator)
    assert.match(result.recommendations[0], /Download risk is unknown/, indicator)
  }
  for (const path of ['torrent', 'magnet-link', 'software-keygen', 'game-repack', 'cracked-software']) {
    assert(scanUrl(`https://example.com/${path}`).details.categories.includes('piracy-content'), path)
  }
})

test('normal banking, login instructions and security education remain benign', () => {
  for (const content of [
    'Your bank payment was received. View your account at https://online.bdo.com.ph/login.',
    'Enter your password on https://accounts.google.com/login.',
    'Never share your password or OTP. Your bank will never ask you to send your PIN.',
    'Scammers ask you to share your password. Beware of urgent account suspended messages.',
    'Do not send your credit card number. This is a phishing warning.',
    'Huwag ibigay ang iyong OTP o password. Hindi hihingin ng bangko ang iyong PIN.',
    'Bank support: user@example.com. Login, passwords, banking and payment security education.',
    'An urgent meeting is scheduled now. Discuss the bank login support page.',
  ]) assert.equal(scanMessage(content).status, 'Safe', content)
})

test('English and Filipino requests to disclose secrets are dangerous without links', () => {
  for (const content of [
    'Please send your password to our support team.',
    'Reply with your one-time code immediately.',
    'Ibigay mo ang iyong OTP ngayon.',
    'Pakisend ang password mo para ma-verify ang account.',
    'Ipadala sa amin ang iyong PIN agad.',
    'Ang OTP mo ay pakibigay sa amin.',
    'Never share your OTP with others. But send your password to us now.',
  ]) assert.equal(scanMessage(content).status, 'Dangerous', content)
})

test('sensitive information and account pressure combine; prize mentions alone do not', () => {
  assert.equal(scanMessage('Send your credit card number now or your account will be suspended.').status, 'Dangerous')
  assert.equal(scanMessage('Pay a processing fee to receive your prize.').status, 'Dangerous')
  assert.equal(scanMessage('The lottery prize and jackpot were discussed in the news.').score, 100)
})

test('contextual parcel, card-photo, prize and account requests produce bounded explainable risk', () => {
  const cases = [
    ['parcel card entry', 'Your parcel is held. Enter your credit card at this unfamiliar link https://parcel-payment.test/release to release it.', 'payment-card or payment details', 'parcel or delivery payment context'],
    ['redelivery card photos', 'A redelivery fee is due. Upload front and back photos of your payment card at https://redelivery-fee.test/pay.', 'payment-card photo or image', 'parcel or delivery payment context'],
    ['employment card photos', 'Congratulations on the remote job. Send photos of the front and back of your debit card to finish salary setup.', 'payment-card photo or image', 'employment lure with an excessive card-photo request'],
    ['prize card information', 'You won a reward. Send your credit card information to claim it.', 'payment-card or payment details', 'prize or reward claim'],
    ['account verification card details', 'Verify your account. Provide your payment card information at this unfamiliar link https://account-check.test/verify.', 'payment-card or payment details', 'account-verification lure with a payment-data link'],
  ]
  for (const [name, input, requestedData, context] of cases) {
    const scan = scanMessage(input)
    const detection = scan.details.findings.find((item) => item.code === 'sensitive-data-context')
    const requestFinding = scan.details.findings.find((item) => item.code === 'sensitive-data-request')
    const result = attachThreatClassification('Message', scan)
    assert.equal(detection?.deduction, 12, name)
    assert.equal(requestFinding?.deduction, 12, name)
    assert.equal(requestFinding.evidence.requestedData, requestedData, name)
    assert.ok(detection.evidence.contexts.includes(context), name)
    assert.equal(scan.score, 76, name)
    assert.equal(scan.status, 'Suspicious', name)
    assert.equal(result.details.threatClassification.threatName, 'Suspected phishing message', name)
    assert.equal(result.details.threatClassification.confidence, 'Medium', name)
    assert.ok(result.details.threatClassification.whyDetected.some((item) => item.includes(context)), name)
  }
})

test('sensitive-data requests without context stay informational or low-confidence without double-counting', () => {
  for (const input of [
    'Please upload a photo of both sides of your payment card.',
    'Please send a photo of your passport.',
    "Please upload your driver's license for the file.",
  ]) {
    const scan = scanMessage(input)
    assert.equal(scan.status, 'Safe', input)
    assert.equal(scan.score, 100, input)
    assert.ok(scan.details.findings.some((item) => item.code === 'sensitive-data-request' && item.deduction === 0), input)
    assert.equal(attachThreatClassification('Message', scan).details.threatClassification.threatName, 'No threat identified', input)
  }

  const explicitNumberRequest = scanMessage('Please send your credit card number.')
  const classification = attachThreatClassification('Message', explicitNumberRequest).details.threatClassification
  assert.equal(explicitNumberRequest.score, 70)
  assert.equal(explicitNumberRequest.status, 'Suspicious')
  assert.equal(classification.threatName, 'Sensitive financial-information request')
  assert.equal(classification.confidence, 'Low')
  assert.ok(!classification.threatName.toLowerCase().includes('phishing'))

  const contextualExistingRule = scanMessage('Provide your credit card details at this unfamiliar link https://parcel-payment.test/release for your parcel.')
  assert.equal(contextualExistingRule.score, 70)
  assert.deepEqual(contextualExistingRule.details.findings.filter((item) => ['financial-request', 'contextual-sensitive-data-request'].includes(item.code)).map((item) => item.deduction), [30, 0])

  const unrelatedContext = scanMessage('Your parcel arrives tomorrow. The team meeting is Friday. Please upload front and back photos of your payment card.')
  assert.equal(unrelatedContext.score, 100)
  assert.equal(unrelatedContext.status, 'Safe')
  assert.ok(!unrelatedContext.details.findings.some((item) => item.code === 'sensitive-data-context'))
})

test('benign delivery, verified-app, employer, discussion and warning messages stay safe', () => {
  const cases = [
    'Use the official carrier app to check your parcel tracking status.',
    'Your customs fee can be paid in the official carrier app.',
    'Open the verified BDO bank app to upload your passport for identity verification.',
    'As part of established employee onboarding, upload a photo of your government-issued ID through the verified HR portal.',
    'Our team compared credit card rewards and discussed card photos for the training presentation.',
    'Never share your credit card information. Scammers may ask you to upload photos of both sides of your card.',
    'Security training explains that phishing messages may say “send your card details to claim a prize.”',
    'Your parcel is delayed. Check your tracking status in the carrier app.',
  ]
  for (const input of cases) {
    const scan = scanMessage(input)
    assert.equal(scan.status, 'Safe', input)
    assert.ok(scan.score >= 80, input)
    assert.ok(!scan.details.findings.some((item) => item.code === 'sensitive-data-context' && item.deduction > 0), input)
  }
})

test('negated, quoted and educational sensitive-data requests do not become active requests', () => {
  const cases = [
    'Do not upload a passport photo or card details to an unfamiliar link.',
    'Never send photos of both sides of your credit card to anyone.',
    'The forwarded message says "Send your credit card number now to claim a prize." Do not comply.',
    'Scammers ask people to upload identity documents and card photos; security training says never comply.',
  ]
  for (const input of cases) {
    const scan = scanMessage(input)
    assert.equal(scan.status, 'Safe', input)
    assert.equal(scan.score, 100, input)
    assert.ok(!scan.details.findings.some((item) => ['sensitive-data-request', 'contextual-sensitive-data-request', 'financial-request', 'advance-fee'].includes(item.code)), input)
  }
})

test('extraction excludes emails, normalizes duplicates and strips punctuation', () => {
  assert.deepEqual(extractLinks('a@example.com user@www.example.net mailto:help@bank.co.uk'), [])
  assert.deepEqual(extractLinks('See (https://Example.com/login), https://example.com/login. example.com/login! www.example.org/path;'), [
    'https://Example.com/login', 'www.example.org/path',
  ])
  assert.deepEqual(extractLinks('https://example.org/wiki/Test_(thing).'), ['https://example.org/wiki/Test_(thing)'])
  assert.deepEqual(extractLinks('https://paypal.com@evil.example/login'), ['https://paypal.com@evil.example/login'])
})

test('message and email retain strongest dangerous link and content scores', () => {
  const dangerous = 'https://paypal.example.net/login'
  const body = `Meeting notes: https://example.org/ ${dangerous} https://google.com/`
  const linkScore = scanUrl(dangerous).score
  const message = scanMessage(body)
  const email = analyzeEmail({ sender: 'person@example.org', subject: 'Meeting', body })
  assert.equal(message.score, linkScore)
  assert.equal(email.score, linkScore)
  assert.equal(email.status, 'Dangerous')
  const secretEmail = analyzeEmail({ sender: 'support@google.com', body: 'Send us your password.' })
  assert.equal(secretEmail.status, 'Dangerous')
  assert.equal(secretEmail.score, scanMessage('Send us your password.').score)
})

test('missing sender, free mailbox support and educational messages do not block', () => {
  assert.equal(analyzeEmail({ body: 'Hello, the meeting is at noon.' }).score, 100)
  assert.equal(analyzeEmail({ sender: 'support@gmail.com', body: 'Hello, the meeting is at noon.' }).score, 100)
  assert.equal(analyzeEmail({ body: 'Never send your OTP. Bank support will never ask for a password.' }).score, 100)
  assert(analyzeEmail({ body: 'Hello' }).details.coverage.limitations.includes('Sender address was not supplied.'))
  const claimed = analyzeEmail({ sender: 'PayPal Support <help@example.org>', body: 'Verify your account at https://example.org/account.' })
  assert(claimed.details.findings.some((item) => item.code === 'sender-brand-claim'))
})

test('all APIs are synchronous and return local coverage and structured evidence', () => {
  for (const result of [scanUrl('https://paypa1.com/login'), scanMessage('Send your OTP.'), analyzeEmail({ body: 'Send your OTP.' })]) {
    assert.equal(typeof result.then, 'undefined')
    assert.equal(result.details.coverage.status, 'local-only')
    assert.equal(result.details.coverage.checkedProviders, 0)
    assert.equal(result.details.coverage.totalProviders, 0)
    assert(result.details.coverage.limitations.includes('Reputation not checked.'))
    assert(result.details.categories.includes('phishing-indicators'))
    assert(result.details.findings.every((item) => item.code && item.label && Number.isFinite(item.deduction) && item.evidence))
  }
})

test('local scanning is bounded and extraction preserves totals beyond local link cap', () => {
  const text = Array.from({ length: MAX_LINKS + 5 }, (_, i) => `https://example.org/${i}`).join(' ')
  assert.equal(extractLinks(text).length, MAX_LINKS + 5)
  const result = scanMessage(text)
  assert.equal(result.details.links.length, MAX_LINKS)
  assert(result.details.coverage.limitations.some((item) => item.includes('some links were not checked')))
  assert(scanMessage('a'.repeat(MAX_TEXT_LENGTH + 1)).details.coverage.limitations.some((item) => item.includes('first 100000')))
  const longUrl = `https://example.org/${'a'.repeat(MAX_URL_LENGTH)}`
  assert.equal(extractLinks(longUrl).length, 0)
  assert.equal(scanUrl(longUrl).status, 'Suspicious')
  assert(scanMessage(longUrl).details.coverage.limitations.some((item) => item.includes('some links were not checked')))
})
