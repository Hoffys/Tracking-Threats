const apiBaseUrl = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '') ?? ''

const request = async (path, options) => {
  const adminToken = localStorage.getItem('threattrack:admin-token')
  const headers = {
    'Content-Type': 'application/json',
    ...(adminToken ? { 'X-Admin-Token': adminToken } : {}),
    ...(options?.headers ?? {}),
  }

  const response = await fetch(`${apiBaseUrl}/api${path}`, {
    ...options,
    headers,
  })

  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`)
  }

  return response.json()
}

export const apiService = {
  getHealth: () => request('/health'),
  getPublicActivity: (clientId) =>
    request(`/public/activity/${encodeURIComponent(clientId)}`),
  getAlerts: () => request('/alerts'),
  getBlockedThreats: () => request('/blocked-threats'),
  getSafeHosts: () => request('/safe-hosts'),
  getThreatAuditLogs: () => request('/threat-audit-logs'),
  getHistory: () => request('/history'),
  getLiveFeed: () => request('/live-feed'),
  getNotificationSettings: () => request('/notification-settings'),
  getStats: () => request('/stats'),
  getSystemLogs: () => request('/system-logs'),
  clearAlerts: () => request('/alerts', { method: 'DELETE' }),
  clearHistory: () => request('/history', { method: 'DELETE' }),
  clearThreatAuditLogs: () => request('/threat-audit-logs/clear', { method: 'PATCH' }),
  dismissAlert: (id) => request(`/alerts/${id}/dismiss`, { method: 'PATCH' }),
  clearFlaggedThreats: () => request('/blocked-threats/clear-active', { method: 'PATCH' }),
  clearReviewedThreats: () => request('/blocked-threats/clear-reviewed', { method: 'PATCH' }),
  reviewBlockedThreat: (id, status) =>
    request(`/blocked-threats/${id}/review`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),
  saveNotificationSettings: (settings) =>
    request('/notification-settings', {
      method: 'PUT',
      body: JSON.stringify(settings),
    }),
  sendHistoryDigest: () =>
    request('/notification-settings/history-digest', {
      method: 'POST',
    }),
  scanUrl: (url, metadata = {}) =>
    request('/scan/url', {
      method: 'POST',
      body: JSON.stringify({ url, ...metadata }),
    }),
  scanEmail: ({ sender, subject, body, ...metadata }) =>
    request('/scan/email', {
      method: 'POST',
      body: JSON.stringify({ sender, subject, body, ...metadata }),
    }),
  scanMessage: ({ target, content, ...metadata }) =>
    request('/scan/message', {
      method: 'POST',
      body: JSON.stringify({ target, message: content, ...metadata }),
    }),
  scanFile: ({ fileName, mimeType, size, content, sha256, ...metadata }) =>
    request('/scan/file', {
      method: 'POST',
      body: JSON.stringify({ fileName, mimeType, size, content, sha256, ...metadata }),
    }),
}
