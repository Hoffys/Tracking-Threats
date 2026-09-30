import assert from 'node:assert/strict'
import test from 'node:test'
import { isClientCredentialExpired } from './scanRepository.js'

test('client credentials expire only after every recorded activity is stale', () => {
  const previous = process.env.CLIENT_CREDENTIAL_RETENTION_DAYS
  process.env.CLIENT_CREDENTIAL_RETENTION_DAYS = '30'
  try {
    const now = new Date('2026-09-30T00:00:00.000Z')
    assert.equal(isClientCredentialExpired({ created_at: '2026-01-01T00:00:00.000Z', last_seen_at: '2026-08-01T00:00:00.000Z' }, now), true)
    assert.equal(isClientCredentialExpired({ created_at: '2026-01-01T00:00:00.000Z', extension_seen_at: '2026-09-20T00:00:00.000Z' }, now), false)
  } finally {
    if (previous === undefined) delete process.env.CLIENT_CREDENTIAL_RETENTION_DAYS
    else process.env.CLIENT_CREDENTIAL_RETENTION_DAYS = previous
  }
})
