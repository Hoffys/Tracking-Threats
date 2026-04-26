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
  getHistory: () => request('/history'),
  getLiveFeed: () => request('/live-feed'),
  getStats: () => request('/stats'),
  getSystemLogs: () => request('/system-logs'),
  clearHistory: () => request('/history', { method: 'DELETE' }),
  dismissAlert: (id) => request(`/alerts/${id}/dismiss`, { method: 'PATCH' }),
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
}
