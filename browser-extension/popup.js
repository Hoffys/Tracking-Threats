const message = document.querySelector('#message')
const pill = document.querySelector('#pill')
const openApp = document.querySelector('#openApp')
const inspectPage = document.querySelector('#inspectPage')
const inspectionNote = document.querySelector('#inspectionNote')

inspectPage.addEventListener('click', () => {
  inspectPage.disabled = true
  inspectionNote.textContent = 'Inspecting rendered forms, redirect context, and URL reputation...'
  chrome.runtime.sendMessage({ type: 'inspect-active-page' }, (response) => {
    inspectPage.disabled = false
    if (chrome.runtime.lastError || !response?.ok) {
      inspectionNote.textContent = `Could not inspect: ${response?.error ?? chrome.runtime.lastError?.message ?? 'Unknown error'}`
      return
    }
    const scan = response.scan
    const label = scan.status === 'Safe' ? 'Appears safe' : scan.status === 'Dangerous' ? 'Risk detected' : 'Caution'
    inspectionNote.textContent = `${label} - score ${scan.score}/100. Scan finished.`
    pill.textContent = `${label} - ${scan.score}/100`
  })
})

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
  const label = status === 'Safe' ? 'Appears safe'
    : status === 'Dangerous' ? 'Risk detected' : status === 'Suspicious' ? 'Caution' : status
  pill.textContent = `${label} - ${threattrackStatus.lastScore}/100`
  if (['Suspicious', 'Dangerous', 'Blocked'].includes(status)) pill.classList.add('error')
  message.textContent += ` - Scan finished; no further checks are pending. Rule-based score, not a probability. ${coverage ? 'Coverage: ' + coverage.status : 'Coverage not recorded.'}`
  if (coverage) message.textContent += ` ${coverage.checkedProviders}/${coverage.totalProviders} providers checked. ${(coverage.limitations ?? []).join(' ')}`
  if (threattrackStatus.categories?.length) message.textContent += ` Categories: ${threattrackStatus.categories.join(', ')}. Content categories do not establish phishing.`
})
