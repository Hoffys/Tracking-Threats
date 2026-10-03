export const adminClientFilters = [
  { id: 'all', label: 'All Clients' },
  { id: 'linked', label: 'Linked / Active' },
  { id: 'legacy', label: 'Legacy / Unlinked' },
]

export const clientOnlineWindowMs = 10 * 60 * 1000

const validTimestamp = (value) => {
  const timestamp = value ? Date.parse(value) : Number.NaN
  return Number.isFinite(timestamp) ? timestamp : null
}

export const isLinkedActiveClient = (client) =>
  client?.accessStatus === 'active' && Boolean(client?.deviceId)

export function filterAdminClients(clients, filter = 'linked') {
  if (filter === 'all') return clients
  return clients.filter((client) =>
    filter === 'legacy' ? !isLinkedActiveClient(client) : isLinkedActiveClient(client))
}

export function formatRelativeTime(value, now = Date.now()) {
  const timestamp = validTimestamp(value)
  if (timestamp === null) return null

  const elapsedSeconds = Math.max(0, Math.floor((now - timestamp) / 1000))
  if (elapsedSeconds < 10) return 'Just now'
  if (elapsedSeconds < 60) return `${elapsedSeconds} seconds ago`

  const elapsedMinutes = Math.floor(elapsedSeconds / 60)
  if (elapsedMinutes < 60) {
    return `${elapsedMinutes} minute${elapsedMinutes === 1 ? '' : 's'} ago`
  }

  const elapsedHours = Math.floor(elapsedMinutes / 60)
  if (elapsedHours < 24) {
    return `${elapsedHours} hour${elapsedHours === 1 ? '' : 's'} ago`
  }

  const elapsedDays = Math.floor(elapsedHours / 24)
  return `${elapsedDays} day${elapsedDays === 1 ? '' : 's'} ago`
}

export function getLatestClientActivity(client) {
  const timestamps = [client?.lastSeenAt, client?.extensionLastSeenAt]
    .map((value) => ({ value, timestamp: validTimestamp(value) }))
    .filter((entry) => entry.timestamp !== null)
    .sort((a, b) => b.timestamp - a.timestamp)
  return timestamps[0]?.value ?? null
}

export function getClientPresence(client, now = Date.now()) {
  const heartbeatAt = client?.extensionLastSeenAt
  const heartbeatTimestamp = validTimestamp(heartbeatAt)
  const age = heartbeatTimestamp === null ? Number.POSITIVE_INFINITY : Math.max(0, now - heartbeatTimestamp)

  return {
    heartbeatAt: heartbeatTimestamp === null ? null : heartbeatAt,
    isOnline: isLinkedActiveClient(client) && age <= clientOnlineWindowMs,
    relative: heartbeatTimestamp === null ? 'No heartbeat' : formatRelativeTime(heartbeatAt, now),
  }
}
