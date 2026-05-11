const params = new URLSearchParams(window.location.search)
const blockedHost = params.get('host') || ''
const APP_URL = 'http://localhost:5173/'

let blockedUrl = params.get('url') || ''

function getDetailsUrl({ page = 'history', url = '', host = '' } = {}) {
  const detailsUrl = new URL(APP_URL)
  detailsUrl.searchParams.set('page', page)
  const target = url || host
  if (target) detailsUrl.searchParams.set('blocked', target)
  return detailsUrl.toString()
}

function renderBlockedPage({ url = '', host = '', status = 'Blocked', score = '0' }) {
  blockedUrl = url

  document.getElementById('blocked-url').textContent =
    blockedUrl || (host ? `Blocked host: ${host}` : 'Unknown URL')
  document.getElementById('score').textContent = `Status: ${status} - Safety score ${score}/100`
  document.getElementById('details-link').href = getDetailsUrl({
    page: 'history',
    url: blockedUrl,
    host,
  })
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
