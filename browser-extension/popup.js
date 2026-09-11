const message = document.querySelector('#message')
const pill = document.querySelector('#pill')
const openApp = document.querySelector('#openApp')

openApp.href = TRACKING_THREATS_CONFIG.APP_URL

chrome.runtime.sendMessage({ type: 'get-linked-app-url' }, (response) => {
  if (response?.ok && response.appUrl) {
    openApp.href = response.appUrl
  }
})

chrome.storage.local.get('threattrackStatus', ({ threattrackStatus }) => {
  if (!threattrackStatus) return

  if (threattrackStatus.appUrl) {
    openApp.href = threattrackStatus.appUrl
  }

  if (!threattrackStatus.ok) {
    message.textContent = threattrackStatus.error
      ? `Scanner offline: ${threattrackStatus.error}`
      : 'Scanner offline'
    pill.textContent = 'Offline'
    pill.classList.add('error')
    return
  }

  message.textContent = threattrackStatus.lastUrl
  pill.textContent = `${threattrackStatus.lastStatus} - ${threattrackStatus.lastScore}/100`
})
