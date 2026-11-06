import assert from 'node:assert/strict'
import test from 'node:test'
import { getPageUrl, resolveRoute } from './routing.js'

const routes = [
  ['dashboard', 'Dashboard'],
  ['learn', 'Learn'],
  ['about', 'About'],
  ['monitor', 'Monitor'],
  ['manual', 'Scan'],
  ['history', 'History'],
  ['alerts', 'Alerts'],
  ['settings', 'Settings'],
  ['admin', 'Admin'],
]

test('every existing page has a direct URL that resolves back to that page', () => {
  for (const [page] of routes) {
    const route = resolveRoute(`http://localhost${getPageUrl(page)}`)
    assert.equal(route.page, page, `${page} should resolve from its URL`)
    assert.equal(route.notFound, undefined)
  }
})

test('root and explicit Dashboard URLs resolve to Dashboard', () => {
  assert.deepEqual(resolveRoute('http://localhost/'), {
    page: 'dashboard', aboutSection: 'methodology',
  })
  assert.deepEqual(resolveRoute('http://localhost/?page=dashboard'), {
    page: 'dashboard', aboutSection: 'methodology',
  })
})

test('About tabs, legacy aliases, and the public privacy URL resolve correctly', () => {
  assert.deepEqual(resolveRoute('http://localhost/?page=about&section=privacy'), {
    page: 'about', aboutSection: 'privacy',
  })
  assert.deepEqual(resolveRoute('http://localhost/?page=methodology'), {
    page: 'about', aboutSection: 'methodology',
  })
  assert.deepEqual(resolveRoute('http://localhost/?page=privacy'), {
    page: 'about', aboutSection: 'privacy',
  })
  assert.deepEqual(resolveRoute('http://localhost/?page=email'), {
    page: 'manual', aboutSection: 'methodology',
  })
  assert.equal(resolveRoute('http://localhost/privacy').page, 'privacyPolicy')
  assert.equal(resolveRoute('http://localhost/privacy/').page, 'privacyPolicy')
})

test('unknown paths and page IDs remain not found instead of silently showing Dashboard', () => {
  assert.equal(resolveRoute('http://localhost/missing').notFound, true)
  assert.equal(resolveRoute('http://localhost/?page=missing').notFound, true)
  assert.equal(resolveRoute('http://localhost/?page=').notFound, true)
})

test('public deployment access behavior remains unchanged for restricted pages', () => {
  assert.deepEqual(resolveRoute('http://localhost/?page=alerts', true), {
    page: 'dashboard', aboutSection: 'methodology', canonicalize: true,
  })
  assert.equal(resolveRoute('http://localhost/?page=admin', true).page, 'admin')
})

test('About tab URLs and dedicated policy URL are stable', () => {
  assert.equal(getPageUrl('about', 'privacy'), '/?page=about&section=privacy')
  assert.equal(getPageUrl('privacyPolicy'), '/privacy')
})

test('Admin has a dedicated route and keeps the legacy query URL', () => {
  assert.equal(getPageUrl('admin'), '/admin')
  assert.equal(resolveRoute('http://localhost/admin').page, 'admin')
  assert.equal(resolveRoute('http://localhost/admin/').page, 'admin')
  assert.equal(resolveRoute('http://localhost/?page=admin').page, 'admin')
})
