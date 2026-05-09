const params = new URLSearchParams(window.location.search)
const blockedHost = params.get('host') || ''

let blockedUrl = params.get('url') || ''

function renderBlockedPage({ url = '', host = '', status = 'Blocked', score = '0' }) {
  blockedUrl = url

  document.getElementById('blocked-url').textContent =
    blockedUrl || (host ? `Blocked host: ${host}` : 'Unknown URL')
  document.getElementById('score').textContent = `Status: ${status} - Safety score ${score}/100`
}

async function loadBlockedContext() {
  if (!blockedHost) {
    renderBlockedPage({
      url: blockedUrl,
      status: params.get('status') || 'Blocked',
      score: params.get('score') || '0',
    })
    return
  }

  const key = `blockedContext:${blockedHost}`
  const stored = await chrome.storage.local.get(key)
  const context = stored[key]

  if (context?.expiresAt && Date.now() <= context.expiresAt) {
    renderBlockedPage(context)
    return
  }

  renderBlockedPage({
    host: blockedHost,
    status: params.get('status') || 'Blocked',
    score: params.get('score') || '0',
  })
}

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

loadBlockedContext()
