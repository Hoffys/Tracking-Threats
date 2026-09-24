const trackingThreatsOrigin = new URL(TRACKING_THREATS_CONFIG.APP_URL).origin

if (window.top === window && window.location.origin === trackingThreatsOrigin) {
  window.addEventListener('message', (event) => {
    if (event.source !== window || event.origin !== trackingThreatsOrigin ||
        event.data?.type !== 'tracking-threats:request-client-credential') return

    chrome.runtime.sendMessage({ type: 'get-client-credential' }, (response) => {
      if (chrome.runtime.lastError || !response?.ok) return
      window.postMessage({
        type: 'tracking-threats:client-credential',
        requestedClientId: event.data.clientId,
        clientId: response.clientId,
        token: response.token,
      }, trackingThreatsOrigin)
    })
  })
}
