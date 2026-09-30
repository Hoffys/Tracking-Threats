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
    const label = scan.status === 'Safe' && scan.categories?.includes('piracy-content') ? 'Download risk unknown'
      : scan.status === 'Safe' ? 'Appears safe' : scan.status === 'Dangerous' ? 'Risk detected' : 'Caution'
    inspectionNote.textContent = `${label} - score ${scan.score}/100. Scan finished.`
    pill.textContent = `${label} - ${scan.score}/100`
    if (scan.categories?.includes('piracy-content')) pill.classList.add('warning')
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
  const label = status === 'Safe' && threattrackStatus.categories?.includes('piracy-content') ? 'Download risk unknown'
    : status === 'Safe' ? 'Appears safe'
    : status === 'Dangerous' ? 'Risk detected' : status === 'Suspicious' ? 'Caution' : status
  pill.textContent = `${label} - ${threattrackStatus.lastScore}/100`
  if (['Suspicious', 'Dangerous', 'Blocked'].includes(status)) pill.classList.add('error')
  if (status === 'Safe' && threattrackStatus.categories?.includes('piracy-content')) pill.classList.add('warning')
  message.textContent += ` - Scan finished; no further checks are pending. Rule-based score, not a probability. ${coverage ? 'Coverage: ' + coverage.status : 'Coverage not recorded.'}`
  if (coverage) message.textContent += ` ${coverage.checkedProviders}/${coverage.totalProviders} providers checked. ${(coverage.limitations ?? []).join(' ')}`
  if (threattrackStatus.categories?.length) message.textContent += ` Categories: ${threattrackStatus.categories.join(', ')}. Content categories do not establish phishing.`
  if (threattrackStatus.categories?.includes('piracy-content')) message.textContent += ' No strong phishing indicators were found, but the download risk is unknown. Piracy-related sources may involve malware, fake mirrors, tampered files, or copyright risk.'
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