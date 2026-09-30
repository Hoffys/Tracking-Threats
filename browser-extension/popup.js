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
  const status = threattrackStatus.lastStatus
  // The compact activity record may predate coverage reporting.
  const coverage = threattrackStatus.coverage
  const incomplete = coverage?.status !== 'complete'
  const label = status === 'Safe' ? (incomplete ? 'Incomplete checks' : 'No strong indicators')
    : status === 'Dangerous' ? 'Risk detected' : status === 'Suspicious' ? 'Caution' : status
  pill.textContent = `${label} - ${threattrackStatus.lastScore}/100`
  if (incomplete || ['Suspicious', 'Dangerous', 'Blocked'].includes(status)) pill.classList.add('error')
  message.textContent += ` ? Rule-based score, not a probability. ${coverage ? 'Coverage: ' + coverage.status : 'Coverage not recorded.'}`
  if (coverage) message.textContent += ` ${coverage.checkedProviders}/${coverage.totalProviders} providers checked. ${(coverage.limitations ?? []).join(' ')}`
  if (threattrackStatus.categories?.length) message.textContent += ` Categories: ${threattrackStatus.categories.join(', ')}. Content categories do not establish phishing.`
})
