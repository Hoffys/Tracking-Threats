import assert from 'node:assert/strict'
import test from 'node:test'
import { enrichEmailAuthentication, verifyEmailAuthentication } from './emailAuthentication.js'

test('raw email authentication converts aligned pass results without deductions', async () => {
  const result = await verifyEmailAuthentication({ rawEmail: 'From: user@example.com\r\n\r\nHello' }, async () => ({
    dkim: { results: [{ status: { result: 'pass' }, signingDomain: 'example.com' }] },
    spf: { status: { result: 'pass' } }, dmarc: { status: { result: 'pass' }, domain: 'example.com', policy: 'reject' },
  }))
  assert.equal(result.checked, true)
  assert.equal(result.deduction, 0)
  assert.equal(result.authentication.dmarc, 'pass')
})

test('DMARC and DKIM failures lower an email result', async () => {
  const base = { score: 100, status: 'Safe', warningSigns: [], details: { threatIntel: [], emailBreakdown: {} } }
  const result = await enrichEmailAuthentication({}, base, async () => ({
    provider: 'Email authentication', checked: true, found: true, deduction: 65,
    warning: 'DMARC authentication failed; DKIM signature verification failed',
    authentication: { dkim: 'fail', spf: 'not-checked', dmarc: 'fail' },
  }))
  assert.equal(result.score, 35)
  assert.equal(result.status, 'Dangerous')
  assert.equal(result.details.emailAuthentication.dmarc, 'fail')
})

test('copied email text does not pretend authentication was checked', async () => {
  const result = await verifyEmailAuthentication({ rawEmail: '' })
  assert.equal(result.checked, false)
  assert.match(result.skipped, /Raw RFC 822/)
})
