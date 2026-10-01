import assert from 'node:assert/strict'
import test from 'node:test'
import { scanUrl, MAX_LINKS, MAX_TEXT_LENGTH, MAX_URL_LENGTH, piracySiteIndicators } from './urlScanner.js'
import { scanMessage, extractLinks } from './messageScanner.js'
import { analyzeEmail } from './emailAnalyzer.js'

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
