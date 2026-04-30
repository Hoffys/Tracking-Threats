const request = async (path, options) => {
  const response = await fetch(`/api${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })

  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`)
  }

  return response.json()
}

export const apiService = {
  getAlerts: () => request('/alerts'),
  getBlockedThreats: () => request('/blocked-threats'),
  getThreatAuditLogs: () => request('/threat-audit-logs'),
  getHistory: () => request('/history'),
  getLiveFeed: () => request('/live-feed'),
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
  scanUrl: (url) =>
    request('/scan/url', {
      method: 'POST',
      body: JSON.stringify({ url }),
    }),
  scanEmail: ({ sender, subject, body }) =>
    request('/scan/email', {
      method: 'POST',
      body: JSON.stringify({ sender, subject, body }),
    }),
  scanMessage: ({ target, content }) =>
    request('/scan/message', {
      method: 'POST',
      body: JSON.stringify({ target, message: content }),
    }),
  scanFile: ({ fileName, mimeType, size, content }) =>
    request('/scan/file', {
      method: 'POST',
      body: JSON.stringify({ fileName, mimeType, size, content }),
    }),
}
