import assert from 'node:assert/strict'
import test from 'node:test'
import {
  compareExtensionVersions,
  selectPublicAnnouncements,
  validateAnnouncementInput,
} from './announcementService.js'

const row = (changes = {}) => ({
  id: 'an_0123456789abcdef0123456789abcdef',
  type: 'update',
  title: 'Extension update available',
  message: 'Install the latest extension package.',
  priority: 'important',
  target_version: '1.0.35',
  is_active: 1,
  published_at: '2026-10-03T10:00:00.000Z',
  expires_at: null,
  created_at: '2026-10-03T10:00:00.000Z',
  updated_at: '2026-10-03T10:00:00.000Z',
  ...changes,
})

test('extension versions compare numerically instead of lexicographically', () => {
  assert.equal(compareExtensionVersions('1.0.35', '1.0.34'), 1)
  assert.equal(compareExtensionVersions('1.0.9', '1.0.10'), -1)
  assert.equal(compareExtensionVersions('1.0.35.0', '1.0.35'), 0)
})

test('announcement validation requires safe bounded fields and update versions', () => {
  assert.deepEqual(validateAnnouncementInput({
    type: 'update',
    title: 'Extension v1.0.35',
    message: 'Security and Gmail monitoring improvements.',
    priority: 'important',
    targetVersion: '1.0.35',
    expiresAt: null,
    isActive: true,
  }), {
    type: 'update',
    title: 'Extension v1.0.35',
    message: 'Security and Gmail monitoring improvements.',
    priority: 'important',
    targetVersion: '1.0.35',
    expiresAt: null,
    isActive: true,
  })
  assert.throws(() => validateAnnouncementInput({
    type: 'update', title: 'Missing version', message: 'No version.', priority: 'normal', isActive: true,
  }), /target version/i)
  assert.throws(() => validateAnnouncementInput({
    type: 'html', title: 'Invalid type', message: 'No.', priority: 'normal', isActive: true,
  }), /type/i)
})

test('public announcements hide drafts, expired items, future items, and installed updates', () => {
  const now = Date.parse('2026-10-03T12:00:00.000Z')
  const rows = [
    row(),
    row({ id: 'an_1123456789abcdef0123456789abcdef', type: 'general', target_version: null }),
    row({ id: 'an_2123456789abcdef0123456789abcdef', is_active: 0 }),
    row({ id: 'an_3123456789abcdef0123456789abcdef', expires_at: '2026-10-03T11:00:00.000Z' }),
    row({ id: 'an_4123456789abcdef0123456789abcdef', published_at: '2026-10-04T10:00:00.000Z' }),
  ]

  const outdated = selectPublicAnnouncements(rows, '1.0.34', now)
  assert.equal(outdated.updateAvailable, true)
  assert.equal(outdated.latestVersion, '1.0.35')
  assert.deepEqual(outdated.announcements.map((item) => item.id), [rows[0].id, rows[1].id])

  const current = selectPublicAnnouncements(rows, '1.0.35', now)
  assert.equal(current.updateAvailable, false)
  assert.deepEqual(current.announcements.map((item) => item.id), [rows[1].id])
})
