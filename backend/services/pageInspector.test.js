import assert from 'node:assert/strict'
import test from 'node:test'
import { enrichPageInspection, inspectHtml, inspectPage, isPublicAddress, pageSnapshotResult } from './pageInspector.js'

test('page inspection rejects private and reserved address ranges', () => {
  for (const address of ['127.0.0.1', '10.1.2.3', '169.254.1.1', '172.16.0.1', '192.168.1.1', '::1', 'fd00::1', 'fe80::1', '2001:db8::1']) {
    assert.equal(isPublicAddress(address), false, address)
  }
  assert.equal(isPublicAddress('8.8.8.8'), true)
  assert.equal(isPublicAddress('2606:4700:4700::1111'), true)
})

test('static page inspection detects external credential forms and redirect tricks', () => {
  const result = inspectHtml(`<!doctype html><title>Verify your bank login</title>
    <form action="https://collector.invalid/submit"><input type="password"></form>
    <meta http-equiv="refresh" content="0;url=https://elsewhere.invalid/">`, 'https://bank.example/login')
  assert.equal(result.passwordFields, 1)
  assert.equal(result.externalFormActions, 1)
  assert.equal(result.externalMetaRefresh, true)
  assert.ok(result.findings.reduce((sum, item) => sum + item.deduction, 0) >= 50)
})

test('redirect inspection is bounded and only follows HTTPS', async () => {
  const responses = new Map([
    ['https://one.example/', { status: 302, headers: { location: 'https://two.example/login' }, body: '' }],
    ['https://two.example/login', { status: 200, headers: { 'content-type': 'text/html' }, body: '<form><input type=password></form> login' }],
  ])
  const result = await inspectPage('https://one.example/', async (url) => responses.get(url))
  assert.equal(result.checked, true)
  assert.equal(result.redirects.length, 1)
  await assert.rejects(() => inspectPage('https://one.example/', async () => ({ status: 302, headers: { location: 'http://unsafe.example/' }, body: '' })), /left HTTPS/)
})

test('page evidence can lower a previously safe URL result', async () => {
  const base = { score: 100, status: 'Safe', risk: 'low', action: 'Allowed', warningSigns: [], recommendations: [], details: { threatIntel: [] } }
  const result = await enrichPageInspection('https://example.com/', base, async () => ({
    provider: 'Page inspection', checked: true, found: true, deduction: 60,
    warning: 'Password form submits to a different host', inspection: { findings: [{ label: 'Password form submits to a different host' }] }, redirects: [], finalOrigin: 'https://example.com',
  }))
  assert.equal(result.score, 40)
  assert.equal(result.status, 'Dangerous')
})

test('rendered snapshot detects a cross-host password form without accepting raw HTML', () => {
  const result = pageSnapshotResult({ passwordFields: 1, externalFormActions: 1, credentialLanguage: true,
    title: 'Login', redirectChain: ['https://one.example/', 'https://two.example/login'], rawHtml: '<secret>' })
  assert.equal(result.deduction, 50)
  assert.deepEqual(result.redirects, ['https://one.example', 'https://two.example'])
  assert.equal(Object.hasOwn(result.inspection, 'rawHtml'), false)
})
