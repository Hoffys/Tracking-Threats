const params = new URLSearchParams(window.location.search)
const blockedUrl = params.get('url') || ''
const blockedHost = params.get('host') || ''

document.getElementById('blocked-url').textContent =
  blockedUrl || (blockedHost ? `Blocked host: ${blockedHost}` : 'Unknown URL')
document.getElementById('score').textContent = `Status: ${
  params.get('status') || 'Blocked'
} - Safety score ${params.get('score') || '0'}/100`

document.getElementById('continue-button').addEventListener('click', () => {
  if (!blockedUrl && !blockedHost) return

  chrome.runtime.sendMessage(
    { type: 'unblock-site', url: blockedUrl, host: blockedHost },
    () => {
      if (blockedUrl) {
        window.location.href = blockedUrl
      } else if (blockedHost) {
        window.location.href = `https://${blockedHost}/`
      }
    },
  )
})
