const message = document.querySelector('#message')
const pill = document.querySelector('#pill')
const openApp = document.querySelector('#openApp')
const inspectPage = document.querySelector('#inspectPage')
const inspectionNote = document.querySelector('#inspectionNote')
const announcementButton = document.querySelector('#announcementButton')
const announcementBadge = document.querySelector('#announcementBadge')
const announcementPanel = document.querySelector('#announcementPanel')
const announcementStatus = document.querySelector('#announcementStatus')
const announcementList = document.querySelector('#announcementList')
const installedVersion = chrome.runtime.getManifest().version
const announcementReadKey = 'trackingThreatsReadAnnouncements'
let currentAnnouncements = []

document.querySelector('#installedVersion').textContent = `Extension v${installedVersion}`

function createAnnouncementCard(announcement) {
  const card = document.createElement('article')
  card.className = 'announcement-card'

  const meta = document.createElement('span')
  meta.className = 'announcement-meta'
  meta.textContent = [announcement.type, announcement.priority, announcement.targetVersion ? `v${announcement.targetVersion}` : '']
    .filter(Boolean).join(' · ')

  const title = document.createElement('strong')
  title.textContent = announcement.title

  const body = document.createElement('p')
  body.textContent = announcement.message

  card.append(meta, title, body)
  if (announcement.type === 'update' && announcement.targetVersion) {
    const update = document.createElement('a')
    update.className = 'announcement-update'
    update.href = `${TRACKING_THREATS_CONFIG.API_BASE_URL.replace(/\/$/, '')}/api/public/extension/download`
    update.target = '_blank'
    update.rel = 'noopener noreferrer'
    update.textContent = `Download v${announcement.targetVersion}`
    card.appendChild(update)
  }
  return card
}

async function markCurrentAnnouncementsRead() {
  if (currentAnnouncements.length === 0) return
  const stored = await chrome.storage.local.get(announcementReadKey)
  const readIds = new Set(Array.isArray(stored[announcementReadKey]) ? stored[announcementReadKey] : [])
  currentAnnouncements.forEach((announcement) => readIds.add(announcement.id))
  await chrome.storage.local.set({
    [announcementReadKey]: Array.from(readIds).slice(-100),
  })
  announcementBadge.hidden = true
}

async function renderAnnouncements(payload) {
  currentAnnouncements = Array.isArray(payload?.announcements) ? payload.announcements : []
  const stored = await chrome.storage.local.get(announcementReadKey)
  const readIds = new Set(Array.isArray(stored[announcementReadKey]) ? stored[announcementReadKey] : [])
  const unread = currentAnnouncements.filter((announcement) => !readIds.has(announcement.id))

  announcementBadge.hidden = unread.length === 0
  announcementBadge.textContent = unread.length > 9 ? '9+' : String(unread.length)
  announcementList.replaceChildren(...currentAnnouncements.map(createAnnouncementCard))
  announcementStatus.textContent = currentAnnouncements.length === 0
    ? 'No new announcements. Your extension is up to date.'
    : payload.updateAvailable
      ? `Update available. Installed v${installedVersion}; latest v${payload.latestVersion}.`
      : `${currentAnnouncements.length} announcement${currentAnnouncements.length === 1 ? '' : 's'}.`
  if (!announcementPanel.hidden) await markCurrentAnnouncementsRead()
}

async function loadAnnouncements() {
  try {
    const apiBase = TRACKING_THREATS_CONFIG.API_BASE_URL.replace(/\/$/, '')
    const response = await fetch(`${apiBase}/api/public/announcements?version=${encodeURIComponent(installedVersion)}`, {
      cache: 'no-store',
    })
    if (!response.ok) throw new Error(`Update service returned ${response.status}`)
    await renderAnnouncements(await response.json())
  } catch {
    announcementStatus.textContent = 'Announcements are temporarily unavailable.'
    announcementBadge.hidden = true
  }
}

announcementButton.addEventListener('click', async () => {
  const opening = announcementPanel.hidden
  announcementPanel.hidden = !opening
  announcementButton.setAttribute('aria-expanded', String(opening))
  if (opening) await markCurrentAnnouncementsRead()
})

loadAnnouncements()

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
    pill.classList.remove('error', 'warning')
    const hasContentWarning = scan.categories?.some((category) => typeof category === 'string' && category.endsWith('-content'))
    const piracyWarning = scan.status === 'Safe' && scan.categories?.includes('piracy-content')
    const label = piracyWarning ? 'Piracy warning'
      : scan.status === 'Safe' && hasContentWarning ? 'Content warning'
      : scan.status === 'Safe' ? 'Appears safe' : scan.status === 'Dangerous' ? 'Risk detected' : 'Caution'
    inspectionNote.textContent = piracyWarning
      ? `Piracy-related content warning. URL phishing safety score ${scan.score}/100; this does not rate downloads. The file was not scanned. Scan the actual file before opening it. Scan finished.`
      : `${label} - safety score ${scan.score}/100. ${scan.threatName ? `Threat name: ${scan.threatName}. Threat type: ${scan.threatType}. ${scan.whyDetected?.[0] ?? ''}` : ''} Scan finished.`
    pill.textContent = piracyWarning ? 'Piracy warning - file not scanned' : `${label} - ${scan.score}/100`
    if (['Dangerous', 'Blocked'].includes(scan.status)) pill.classList.add('error')
    if (scan.status === 'Suspicious') pill.classList.add('warning')
    if (scan.status === 'Safe' && hasContentWarning) pill.classList.add('warning')
  })
})

openApp.href = TRACKING_THREATS_CONFIG.APP_URL

chrome.runtime.sendMessage({ type: 'get-linked-app-url' }, (response) => {
  if (response?.ok && response.appUrl) {
    openApp.href = response.appUrl
  }
})

function renderStatus(threattrackStatus) {
  if (!threattrackStatus) return
  pill.classList.remove('error', 'warning')

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
  const hasContentWarning = threattrackStatus.categories?.some((category) => typeof category === 'string' && category.endsWith('-content'))
  const piracyWarning = status === 'Safe' && threattrackStatus.categories?.includes('piracy-content')
  const label = piracyWarning ? 'Piracy warning'
    : status === 'Safe' && hasContentWarning ? 'Content warning'
    : status === 'Safe' ? 'Appears safe'
    : status === 'Dangerous' ? 'Risk detected' : status === 'Suspicious' ? 'Caution' : status
  pill.textContent = piracyWarning ? 'Piracy warning - file not scanned' : `${label} - ${threattrackStatus.lastScore}/100`
  if (['Suspicious', 'Dangerous', 'Blocked'].includes(status)) pill.classList.add('error')
  if (status === 'Safe' && hasContentWarning) pill.classList.add('warning')
  message.textContent += piracyWarning
    ? ` - URL phishing safety score ${threattrackStatus.lastScore}/100; this does not rate downloads. The file was not scanned. ${coverage ? 'Coverage: ' + coverage.status : 'Coverage not recorded.'}`
    : ` - Scan finished; no further checks are pending. Rule-based safety score, not a probability. ${coverage ? 'Coverage: ' + coverage.status : 'Coverage not recorded.'}`
  if (coverage) message.textContent += ` ${coverage.checkedProviders}/${coverage.totalProviders} providers checked. ${(coverage.limitations ?? []).join(' ')}`
  if (threattrackStatus.downloadWarning) message.textContent += ` ${threattrackStatus.downloadWarning}`
  if (threattrackStatus.categories?.length) message.textContent += ` Categories: ${threattrackStatus.categories.join(', ')}. Content categories do not establish phishing.`
  if (threattrackStatus.categories?.includes('piracy-content')) message.textContent += ' No strong phishing indicators were found, but the download risk is unknown. Piracy-related sources may involve malware, fake mirrors, tampered files, or copyright risk.'
  if (threattrackStatus.threatName) message.textContent += ` Threat name: ${threattrackStatus.threatName}.`
  if (threattrackStatus.threatType) message.textContent += ` Threat type: ${threattrackStatus.threatType}.`
  if (threattrackStatus.whyDetected?.length) message.textContent += ` Why: ${threattrackStatus.whyDetected[0]}`
  if (threattrackStatus.confidence) message.textContent += ` Confidence: ${threattrackStatus.confidence}.`
}

chrome.storage.local.get('threattrackStatus', ({ threattrackStatus }) => renderStatus(threattrackStatus))
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.threattrackStatus) renderStatus(changes.threattrackStatus.newValue)
})
const devicePairCodeInput = document.getElementById('devicePairCode')
const linkDeviceButton = document.getElementById('linkDeviceButton')
const devicePairStatus = document.getElementById('devicePairStatus')
const linkedDeviceInfo = document.getElementById('linkedDeviceInfo')
const devicePairForm = document.getElementById('devicePairForm')

const deviceNameInput = document.getElementById('deviceNameInput')
const createDeviceButton = document.getElementById('createDeviceButton')
const createDeviceStatus = document.getElementById('createDeviceStatus')
const generatedPairCode = document.getElementById('generatedPairCode')
const generatePairCodeButton = document.getElementById('generatePairCodeButton')
const newPairCodeDisplay = document.getElementById('newPairCodeDisplay')

if (generatePairCodeButton) {
  generatePairCodeButton.addEventListener('click', async () => {
    generatePairCodeButton.disabled = true

    if (newPairCodeDisplay) {
      newPairCodeDisplay.style.display = 'block'
      newPairCodeDisplay.textContent = 'Generating pairing code...'
    }

    try {
      const result = await chrome.runtime.sendMessage({
        type: 'GENERATE_PAIR_CODE',
      })

      if (!result?.ok) {
        if (newPairCodeDisplay) {
          newPairCodeDisplay.textContent =
            result?.error || 'Unable to generate pairing code.'
        }

        return
      }

      if (newPairCodeDisplay) {
        newPairCodeDisplay.textContent =
          `Pairing code: ${result.pairCode} — valid for 10 minutes`
      }
    } catch (error) {
      console.error('Generate pairing code popup error:', error)

      if (newPairCodeDisplay) {
        newPairCodeDisplay.textContent =
          'Unable to communicate with the extension.'
      }
    } finally {
      generatePairCodeButton.disabled = false
    }
  })
}

async function loadLinkedDeviceInfo() {
  const createDeviceSection =
    document.getElementById('createDeviceSection')

  const stored = await chrome.storage.local.get([
    'linkedDeviceId',
    'linkedDeviceName',
    'linkedBrowserName',
  ])

  // NOT LINKED YET
  if (!stored.linkedDeviceId) {
    if (createDeviceSection) {
      createDeviceSection.style.display = 'block'
    }

    if (linkedDeviceInfo) {
      linkedDeviceInfo.style.display = 'none'
    }

    if (devicePairForm) {
      devicePairForm.style.display = 'block'
    }

    if (generatePairCodeButton) {
      generatePairCodeButton.style.display = 'none'
    }

    return
  }

  // ALREADY LINKED
  if (createDeviceSection) {
    createDeviceSection.style.display = 'none'
  }

  if (linkedDeviceInfo) {
    linkedDeviceInfo.style.display = 'block'
    linkedDeviceInfo.textContent =
      `Linked to: ${stored.linkedDeviceName || 'Device'} (${stored.linkedBrowserName || 'Browser'})`
  }

  if (devicePairForm) {
    devicePairForm.style.display = 'none'
  }

  if (generatePairCodeButton) {
    generatePairCodeButton.style.display = 'block'
  }
}

if (linkDeviceButton) {
  linkDeviceButton.addEventListener('click', async () => {
    const pairCode = String(devicePairCodeInput?.value ?? '')
      .trim()
      .toUpperCase()

    if (!/^[A-F0-9]{8}$/.test(pairCode)) {
      devicePairStatus.textContent =
        'Enter a valid 8-character device code.'
      return
    }

    linkDeviceButton.disabled = true
    devicePairStatus.textContent = 'Linking device...'

    try {
      const result = await chrome.runtime.sendMessage({
        type: 'PAIR_DEVICE',
        pairCode,
      })

      if (!result?.ok) {
        devicePairStatus.textContent =
          result?.error || 'Unable to link this browser.'
        return
      }

      devicePairStatus.textContent = 'Device linked successfully.'

      if (devicePairCodeInput) {
        devicePairCodeInput.value = ''
      }

      await loadLinkedDeviceInfo()
    } catch (error) {
      console.error('Pair device popup error:', error)

      devicePairStatus.textContent =
        'Unable to communicate with the extension.'
    } finally {
      linkDeviceButton.disabled = false
    }
  })
}

if (createDeviceButton) {
  createDeviceButton.addEventListener('click', async () => {
    const deviceName = String(deviceNameInput?.value ?? '').trim()

    if (!deviceName) {
      createDeviceStatus.textContent = 'Enter a device name.'
      return
    }

    createDeviceButton.disabled = true
    createDeviceStatus.textContent = 'Creating device...'

    try {
      const result = await chrome.runtime.sendMessage({
        type: 'CREATE_DEVICE',
        deviceName,
      })

      if (!result?.ok) {
        createDeviceStatus.textContent =
          result?.error || 'Unable to create device.'
        return
      }

      createDeviceStatus.textContent =
        `Device created: ${result.device?.deviceName || deviceName}`

      if (result.pairCode && generatedPairCode) {
        generatedPairCode.style.display = 'block'
        generatedPairCode.textContent =
          `Pairing code: ${result.pairCode} — valid for 10 minutes`
      }

      await loadLinkedDeviceInfo()
    } catch (error) {
      console.error('Create device popup error:', error)

      createDeviceStatus.textContent =
        'Unable to communicate with the extension.'
    } finally {
      createDeviceButton.disabled = false
    }
  })
}

loadLinkedDeviceInfo()
