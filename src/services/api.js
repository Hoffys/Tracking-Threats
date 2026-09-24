const apiBaseUrl = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '') ?? ''
export const extensionDownloadUrl = `${apiBaseUrl}/api/public/extension/download`
const clientCredentialKey = 'threattrack:client-credential'
const validClientId = (value) => /^cl_[a-f0-9]{32}$/.test(value ?? '')
const validClientToken = (value) => /^[A-Za-z0-9_-]{40,80}$/.test(value ?? '')
let registrationPromise

const readStoredCredential = () => {
  try {
    const stored = JSON.parse(localStorage.getItem(clientCredentialKey) ?? 'null')
    return validClientId(stored?.clientId) && validClientToken(stored?.token)
      ? stored
      : null
  } catch {
    return null
  }
}

const receiveExtensionCredential = (clientId) => new Promise((resolve) => {
  const finish = (credential) => {
    window.removeEventListener('message', onMessage)
    window.clearTimeout(timeout)
    resolve(credential)
  }
  const onMessage = (event) => {
    if (event.source !== window || event.origin !== window.location.origin ||
        event.data?.type !== 'tracking-threats:client-credential' ||
        (event.data.requestedClientId ?? event.data.clientId) !== clientId ||
        !validClientId(event.data.clientId) || !validClientToken(event.data.token)) return
    finish({ clientId: event.data.clientId, token: event.data.token })
  }
  window.addEventListener('message', onMessage)
  const timeout = window.setTimeout(() => finish(null), 10000)
  window.postMessage({ type: 'tracking-threats:request-client-credential', clientId }, window.location.origin)
})

const request = async (path, options) => {
  const headers = {
    'Content-Type': 'application/json',
    ...(options?.headers ?? {}),
  }

  const response = await fetch(`${apiBaseUrl}/api${path}`, {
    ...options,
    headers,
  })

  if (!response.ok) {
    let message = `API request failed: ${response.status}`
    let code
    try {
      const payload = await response.clone().json()
      if (payload?.error) message = payload.error
      code = payload?.code
    } catch {
      // Keep the status-based message when the backend does not return JSON.
    }
    throw Object.assign(new Error(message), { status: response.status, code })
  }

  return response.json()
}

export const readClientCredential = () => {
  const linkedId = new URLSearchParams(window.location.search).get('client')
  const stored = readStoredCredential()
  if (validClientId(linkedId) && linkedId !== stored?.clientId) return null
  return stored
}

export const clearClientCredential = () => {
  localStorage.removeItem(clientCredentialKey)
}

export const ensureClientCredential = async () => {
  if (!registrationPromise) {
    registrationPromise = (async () => {
      const stored = readClientCredential()
      if (stored) {
        try {
          await request(`/public/clients/${stored.clientId}`, {
            headers: { 'X-Client-Token': stored.token },
            cache: 'no-store',
          })
          return stored
        } catch (error) {
          if (error.status !== 403 ||
              (error.code !== 'CLIENT_ACCESS_DENIED' && error.message !== 'Client access denied')) throw error
        }
      }
      const linkedId = new URLSearchParams(window.location.search).get('client')
      const bridged = validClientId(linkedId)
        ? await receiveExtensionCredential(linkedId)
        : null
      if (validClientId(linkedId) && !bridged) {
        throw new Error('Cannot access extension history. Reload the extension or open the app without the client link.')
      }
      return bridged ?? request('/public/clients', { method: 'POST' })
    })()
      .then((credential) => {
        if (!validClientId(credential.clientId) || !validClientToken(credential.token)) {
          throw new Error('Invalid client credential response')
        }
        localStorage.setItem(clientCredentialKey, JSON.stringify(credential))
        const url = new URL(window.location.href)
        if (validClientId(url.searchParams.get('client')) &&
            url.searchParams.get('client') !== credential.clientId) {
          url.searchParams.set('client', credential.clientId)
          window.history.replaceState(window.history.state, '', url)
        }
        return credential
      })
      .finally(() => { registrationPromise = null })
  }
  return registrationPromise
}

const clientRequest = (path, clientId, options = {}) => {
  if (!clientId) return request(path, options)
  const credential = readClientCredential()
  if (!credential || credential.clientId !== clientId) {
    throw new Error('This browser does not own the requested client history')
  }
  return request(path, {
    ...options,
    headers: { ...options.headers, 'X-Client-Token': credential.token },
  })
}

const adminRequest = (path, token, options = {}) =>
  request(path, {
    ...options,
    headers: { ...options.headers, Authorization: `Bearer ${token}` },
  })

const clientQuery = (clientId) => (clientId ? `?clientId=${encodeURIComponent(clientId)}` : '')

export const apiService = {
  getHealth: () => request('/health'),
  getPublicActivity: (clientId) =>
    clientRequest(`/public/activity/${encodeURIComponent(clientId)}`, clientId),
  deletePublicHistory: (clientId) =>
    clientRequest(`/public/activity/${encodeURIComponent(clientId)}`, clientId, { method: 'DELETE' }),
  deletePublicClientData: (clientId) =>
    clientRequest(`/public/data/${encodeURIComponent(clientId)}`, clientId, { method: 'DELETE' }),
  getAdminOverview: (token) => adminRequest('/admin/overview', token),
  getAdminClients: (token) => adminRequest('/admin/clients', token),
  getAdminClient: (token, clientId) =>
    adminRequest(`/admin/clients/${encodeURIComponent(clientId)}`, token),
  getAdminLogs: (token) => adminRequest('/admin/logs', token),
  deleteAdminClientData: (token, clientId) =>
    adminRequest(`/admin/clients/${encodeURIComponent(clientId)}/data`, token, {
      method: 'DELETE',
      body: JSON.stringify({ confirmClientId: clientId, verifiedRequest: true }),
    }),
  getAlerts: () => request('/alerts'),
  getBlockedThreats: () => request('/blocked-threats'),
  getSafeHosts: () => request('/safe-hosts'),
  getThreatAuditLogs: () => request('/threat-audit-logs'),
  getHistory: () => request('/history'),
  getLiveFeed: () => request('/live-feed'),
  getNotificationSettings: (clientId = '') =>
    clientRequest(`/notification-settings${clientQuery(clientId)}`, clientId),
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
  saveNotificationSettings: (settings, clientId = '') =>
    clientRequest(`/notification-settings${clientQuery(clientId)}`, clientId, {
      method: 'PUT',
      body: JSON.stringify({ ...settings, clientId }),
    }),
  sendHistoryDigest: (settings = {}, clientId = '') =>
    clientRequest(`/notification-settings/history-digest${clientQuery(clientId)}`, clientId, {
      method: 'POST',
      body: JSON.stringify({ ...settings, clientId }),
    }),
  scanUrl: (url, metadata = {}) =>
    clientRequest('/scan/url', metadata.clientId, {
      method: 'POST',
      body: JSON.stringify({ url, ...metadata }),
    }),
  scanEmail: ({ sender, subject, body, ...metadata }) =>
    clientRequest('/scan/email', metadata.clientId, {
      method: 'POST',
      body: JSON.stringify({ sender, subject, body, ...metadata }),
    }),
  scanMessage: ({ target, content, ...metadata }) =>
    clientRequest('/scan/message', metadata.clientId, {
      method: 'POST',
      body: JSON.stringify({ target, message: content, ...metadata }),
    }),
  scanFile: ({ fileName, mimeType, size, content, sha256, ...metadata }) =>
    clientRequest('/scan/file', metadata.clientId, {
      method: 'POST',
      body: JSON.stringify({ fileName, mimeType, size, content, sha256, ...metadata }),
    }),
}
