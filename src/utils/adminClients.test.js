import assert from 'node:assert/strict'
import test from 'node:test'
import {
  filterAdminClients,
  formatRelativeTime,
  getClientPresence,
  getLatestClientActivity,
  isLinkedActiveClient,
} from './adminClients.js'

const now = Date.parse('2026-10-03T12:00:00.000Z')
const linked = {
  clientId: 'cl_linked',
  accessStatus: 'active',
  deviceId: 'device_1',
  lastSeenAt: '2026-10-03T11:59:40.000Z',
  extensionLastSeenAt: '2026-10-03T11:59:30.000Z',
}
const unlinked = { clientId: 'cl_unlinked', accessStatus: 'active', deviceId: null }
const legacy = { clientId: 'cl_legacy', accessStatus: 'legacy', deviceId: null }

test('admin client filters default to linked clients without modifying records', () => {
  const clients = [linked, unlinked, legacy]
  assert.equal(isLinkedActiveClient(linked), true)
  assert.deepEqual(filterAdminClients(clients), [linked])
  assert.deepEqual(filterAdminClients(clients, 'all'), clients)
  assert.deepEqual(filterAdminClients(clients, 'legacy'), [unlinked, legacy])
  assert.equal(clients.length, 3)
})

test('relative time uses readable second, minute, hour, and day labels', () => {
  assert.equal(formatRelativeTime('2026-10-03T11:59:55.000Z', now), 'Just now')
  assert.equal(formatRelativeTime('2026-10-03T11:59:30.000Z', now), '30 seconds ago')
  assert.equal(formatRelativeTime('2026-10-03T11:55:00.000Z', now), '5 minutes ago')
  assert.equal(formatRelativeTime('2026-10-03T10:00:00.000Z', now), '2 hours ago')
  assert.equal(formatRelativeTime('2026-10-02T12:00:00.000Z', now), '1 day ago')
})

test('presence uses the existing extension heartbeat and handles missing timestamps', () => {
  assert.deepEqual(getClientPresence(linked, now), {
    heartbeatAt: linked.extensionLastSeenAt,
    isOnline: true,
    relative: '30 seconds ago',
  })
  assert.deepEqual(getClientPresence(unlinked, now), {
    heartbeatAt: null,
    isOnline: false,
    relative: 'No heartbeat',
  })
  assert.deepEqual(getClientPresence({
    ...linked,
    extensionLastSeenAt: null,
  }, now), {
    heartbeatAt: null,
    isOnline: false,
    relative: 'No heartbeat',
  })
})

test('last active selects the newest valid existing activity timestamp', () => {
  assert.equal(getLatestClientActivity(linked), linked.lastSeenAt)
  assert.equal(getLatestClientActivity({ lastSeenAt: 'invalid', extensionLastSeenAt: null }), null)
})
