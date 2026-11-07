const trackingThreatsOrigin = new URL(TRACKING_THREATS_CONFIG.APP_URL).origin

if (window.top === window && window.location.origin === trackingThreatsOrigin) {
  window.addEventListener('message', (event) => {
    if (event.source !== window || event.origin !== trackingThreatsOrigin ||
        event.data?.type !== 'tracking-threats:request-client-credential') return

    const sendFailure = (code) => window.postMessage({
      type: 'tracking-threats:client-credential-error',
      requestedClientId: event.data.clientId,
      code,
    }, trackingThreatsOrigin)

    try {
      chrome.runtime.sendMessage({ type: 'get-client-credential' }, (response) => {
        if (chrome.runtime.lastError) {
          sendFailure('EXTENSION_UNAVAILABLE')
          return
        }
        if (!response?.ok || !response.clientId || !response.token) {
          sendFailure('CREDENTIAL_UNAVAILABLE')
          return
        }
        window.postMessage({
          type: 'tracking-threats:client-credential',
          requestedClientId: event.data.clientId,
          clientId: response.clientId,
          token: response.token,
        }, trackingThreatsOrigin)
      })
    } catch {
      sendFailure('EXTENSION_UNAVAILABLE')
    }
  })
}
