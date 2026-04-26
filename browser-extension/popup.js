const message = document.querySelector('#message')
const pill = document.querySelector('#pill')
const openApp = document.querySelector('#openApp')

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
