import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import test from 'node:test'

const oldCredential = { clientId: `cl_${'a'.repeat(32)}`, token: 'a'.repeat(43) }
const newCredential = { clientId: `cl_${'b'.repeat(32)}`, token: 'b'.repeat(43) }
const denied = () => Response.json({ error: 'Client access denied', code: 'CLIENT_ACCESS_DENIED' }, { status: 403 })

function extension(fetch) {
  const stored = { threattrackClientId: oldCredential.clientId, threattrackClientToken: oldCredential.token }
  const source = readFileSync(new URL('../../browser-extension/background.js', import.meta.url), 'utf8')
  const sandbox = {
    URL, AbortSignal, fetch, importScripts() {},
    TRACKING_THREATS_CONFIG: { API_BASE_URL: 'https://api.example', APP_URL: 'https://app.example' },
    chrome: {
      runtime: { onMessage: { addListener() {} } },
      storage: { local: {
        get: async () => ({ ...stored }),
        set: async (values) => Object.assign(stored, values),
      } },
    },
  }
  vm.runInNewContext(source.slice(0, source.indexOf('async function hasEmailScanConsent')), sandbox)
  return { scan: sandbox.scanFetch, stored }
}

const scanOptions = (clientId = oldCredential.clientId) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ clientId, url: 'https://example.com', privacyAccepted: true }),
})

test('extension renews a deleted client once for concurrent scans and retries with matching credentials', async () => {
  let registrations = 0
  const successful = []
  const { scan, stored } = extension(async (url, options) => {
    if (url.endsWith('/public/clients')) {
      registrations += 1
      return Response.json(newCredential, { status: 201 })
    }
    const body = JSON.parse(options.body)
    if (body.clientId === oldCredential.clientId) return denied()
    assert.equal(body.clientId, newCredential.clientId)
    assert.equal(options.headers['X-Client-Token'], newCredential.token)
    assert.equal(body.privacyAccepted, true)
    successful.push(url)
    return Response.json({ status: 'Safe' })
  })
  const responses = await Promise.all(['url', 'email', 'file'].map((kind) =>
    scan(`https://api.example/api/scan/${kind}`, scanOptions())))
  assert.equal(responses.every((response) => response.ok), true)
  assert.equal(registrations, 1)
  assert.equal(successful.length, 3)
  assert.equal(stored.threattrackClientId, newCredential.clientId)
  // A download's second scan may still carry the old ID captured before renewal.
  assert.equal((await scan('https://api.example/api/scan/file', scanOptions())).ok, true)
  assert.equal(registrations, 1)
})

test('extension does not rotate identity for rate limits, server errors or unrelated forbidden responses', async () => {
  for (const status of [429, 500, 403]) {
    let calls = 0
    const { scan, stored } = extension(async () => {
      calls += 1
      return Response.json({ error: 'Unavailable' }, { status })
    })
    assert.equal((await scan('https://api.example/api/scan/url', scanOptions())).status, status)
    assert.equal(calls, 1)
    assert.equal(stored.threattrackClientId, oldCredential.clientId)
  }
})

test('extension stops after one retry if the replacement is also rejected', async () => {
  let calls = 0
  const { scan } = extension(async (url) => {
    calls += 1
    return url.endsWith('/public/clients') ? Response.json(newCredential) : denied()
  })
  assert.equal((await scan('https://api.example/api/scan/url', scanOptions())).status, 403)
  assert.equal(calls, 3)
})

test('extension preserves stored credentials when a scan cannot reach the server', async () => {
  const { scan, stored } = extension(async () => { throw new Error('Network unavailable') })
  await assert.rejects(scan('https://api.example/api/scan/url', scanOptions()), /Network unavailable/)
  assert.equal(stored.threattrackClientId, oldCredential.clientId)
})

test('credential bridge returns the replacement ID only to the trusted app window', () => {
  let handler
  const messages = []
  const window = {
    location: { origin: 'https://app.example' },
    addEventListener: (_type, listener) => { handler = listener },
    postMessage: (message) => messages.push(message),
  }
  window.top = window
  const sandbox = {
    URL, window,
    TRACKING_THREATS_CONFIG: { APP_URL: 'https://app.example' },
    chrome: { runtime: { sendMessage: (_message, callback) => callback({ ok: true, ...newCredential }) } },
  }
  vm.runInNewContext(readFileSync(new URL('../../browser-extension/app-bridge.js', import.meta.url), 'utf8'), sandbox)
  const event = {
    source: window, origin: window.location.origin,
    data: { type: 'tracking-threats:request-client-credential', clientId: oldCredential.clientId },
  }
  handler({ ...event, origin: 'https://untrusted.example' })
  assert.equal(messages.length, 0)
  handler(event)
  assert.equal(messages[0].requestedClientId, oldCredential.clientId)
  assert.equal(messages[0].clientId, newCredential.clientId)
})

function getBackgroundCredentialListener(credentials = oldCredential) {
  const source = readFileSync(new URL('../../browser-extension/background.js', import.meta.url), 'utf8')
  const start = source.lastIndexOf('chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {')
  const end = source.indexOf('\nchrome.notifications.onClicked', start)
  assert.notEqual(start, -1)
  assert.notEqual(end, -1)
  let listener
  let verifications = 0
  const sandbox = {
    URL,
    APP_ORIGIN: 'https://app.example',
    chrome: { runtime: { onMessage: { addListener: (callback) => { listener = callback } } } },
    getVerifiedClientCredentials: async () => { verifications += 1; return credentials },
  }
  vm.runInNewContext(source.slice(start, end), sandbox)
  return { listener, get verifications() { return verifications } }
}

const requestBackgroundCredential = (listener, sender) => new Promise((resolve) => {
  const keepsChannelOpen = listener({ type: 'get-client-credential' }, sender, resolve)
  assert.equal(keepsChannelOpen, true)
})

test('background credential listener returns credentials only to the trusted app origin', async () => {
  const bridge = getBackgroundCredentialListener()
  const response = await requestBackgroundCredential(bridge.listener, {
    url: 'https://app.example/page',
  })
  assert.deepEqual(JSON.parse(JSON.stringify(response)), { ok: true, ...oldCredential })
  assert.equal(bridge.verifications, 1)
})

test('background credential listener safely rejects an untrusted origin and missing sender URL', async () => {
  for (const sender of [{ url: 'https://attacker.example/' }, {}, null]) {
    const bridge = getBackgroundCredentialListener()
    const response = await requestBackgroundCredential(bridge.listener, sender)
    assert.deepEqual(JSON.parse(JSON.stringify(response)), { ok: false, error: 'Untrusted page' })
    assert.equal(bridge.verifications, 0)
  }
})

test('content bridge reports credential failures promptly without forwarding secrets or internal errors', () => {
  let handler
  const messages = []
  const window = {
    location: { origin: 'https://app.example' },
    addEventListener: (_type, listener) => { handler = listener },
    postMessage: (message) => messages.push(message),
  }
  window.top = window
  const sandbox = {
    URL, window,
    TRACKING_THREATS_CONFIG: { APP_URL: 'https://app.example/' },
    chrome: { runtime: {
      lastError: null,
      sendMessage: (_message, callback) => callback({
        ok: false,
        error: 'private backend detail',
        clientId: oldCredential.clientId,
        token: oldCredential.token,
      }),
    } },
  }
  vm.runInNewContext(readFileSync(new URL('../../browser-extension/app-bridge.js', import.meta.url), 'utf8'), sandbox)
  const request = {
    source: window,
    origin: window.location.origin,
    data: { type: 'tracking-threats:request-client-credential', clientId: oldCredential.clientId },
  }
  handler({ ...request, origin: 'https://attacker.example' })
  assert.equal(messages.length, 0)
  handler(request)
  assert.deepEqual(JSON.parse(JSON.stringify(messages[0])), {
    type: 'tracking-threats:client-credential-error',
    requestedClientId: oldCredential.clientId,
    code: 'CREDENTIAL_UNAVAILABLE',
  })
  assert.equal(JSON.stringify(messages).includes(oldCredential.token), false)
  assert.equal(JSON.stringify(messages).includes('private backend detail'), false)
})

test('content bridge reports a runtime messaging failure without exposing lastError details', () => {
  let handler
  const messages = []
  const window = {
    location: { origin: 'https://app.example' },
    addEventListener: (_type, listener) => { handler = listener },
    postMessage: (message) => messages.push(message),
  }
  window.top = window
  const sandbox = {
    URL, window,
    TRACKING_THREATS_CONFIG: { APP_URL: 'https://app.example/' },
    chrome: { runtime: {
      lastError: { message: 'sensitive runtime detail' },
      sendMessage: (_message, callback) => callback(undefined),
    } },
  }
  vm.runInNewContext(readFileSync(new URL('../../browser-extension/app-bridge.js', import.meta.url), 'utf8'), sandbox)
  handler({
    source: window,
    origin: window.location.origin,
    data: { type: 'tracking-threats:request-client-credential', clientId: oldCredential.clientId },
  })
  assert.deepEqual(JSON.parse(JSON.stringify(messages[0])), {
    type: 'tracking-threats:client-credential-error',
    requestedClientId: oldCredential.clientId,
    code: 'EXTENSION_UNAVAILABLE',
  })
  assert.equal(JSON.stringify(messages).includes('sensitive runtime detail'), false)
})

function webClient(fetch, linked = false, storedCredential = oldCredential, bridgeCredential = newCredential) {
  const storage = new Map(storedCredential
    ? [['threattrack:client-credential', JSON.stringify(storedCredential)]]
    : [])
  const location = new URL(`https://app.example/?page=history${linked ? `&client=${oldCredential.clientId}` : ''}`)
  const listeners = new Set()
  const window = {
    location, setTimeout, clearTimeout,
    history: { state: null, replaceState: (_state, _unused, url) => { location.href = url.toString() } },
    addEventListener: (_type, handler) => listeners.add(handler),
    removeEventListener: (_type, handler) => listeners.delete(handler),
    postMessage: (message) => queueMicrotask(() => {
      for (const handler of listeners) handler({
        source: window, origin: location.origin,
        data: { type: 'tracking-threats:client-credential', requestedClientId: message.clientId, ...bridgeCredential },
      })
    }),
  }
  const sandbox = {
    URL, URLSearchParams, window, fetch,
    localStorage: { getItem: (key) => storage.get(key), setItem: (key, value) => storage.set(key, value) },
  }
  const source = readFileSync(new URL('../../src/services/api.js', import.meta.url), 'utf8')
    .replaceAll('import.meta.env', 'viteEnv')
    .replaceAll('export const ', 'const ')
  assert.doesNotMatch(source, /import\.meta/)
  const context = {
    ...sandbox,
    viteEnv: { VITE_API_BASE_URL: '', VITE_CHROME_WEB_STORE_URL: '' },
  }
  vm.runInNewContext(`${source}\nglobalThis.ensure = ensureClientCredential; globalThis.apiService = apiService`, context)
  return { ensure: context.ensure, apiService: context.apiService, storage, location }
}

test('web client replaces deleted credentials with a single registration', async () => {
  let registrations = 0
  const { ensure, storage } = webClient(async (url) => {
    if (url.endsWith('/public/clients')) {
      registrations += 1
      return Response.json(newCredential)
    }
    return denied()
  })
  const credentials = await Promise.all([ensure(), ensure()])
  assert.equal(credentials.every((credential) => credential.clientId === newCredential.clientId), true)
  assert.equal(registrations, 1)
  assert.equal(JSON.parse(storage.get('threattrack:client-credential')).clientId, newCredential.clientId)
})

test('linked web app adopts the extension replacement and updates its history link', async () => {
  const { ensure, location } = webClient(async () => denied(), true)
  assert.equal((await ensure()).clientId, newCredential.clientId)
  assert.equal(location.searchParams.get('client'), newCredential.clientId)
  assert.equal(location.searchParams.get('page'), 'history')
})

test('linked app receives extension credentials promptly and retrieves only that client activity', async () => {
  const activity = {
    scans: [{ id: 'scan-1', type: 'URL', source: 'browser-extension', status: 'Safe' }],
    liveFeed: [{ id: 'scan-1', activityType: 'URL', source: 'browser-extension' }],
    stats: { total: 1, liveScanCount: 1 },
  }
  const requests = []
  const { ensure, apiService, location } = webClient(async (url, options = {}) => {
    requests.push({ url, options })
    if (url.endsWith(`/public/clients/${oldCredential.clientId}`)) return denied()
    if (url.endsWith(`/public/activity/${newCredential.clientId}`)) return Response.json(activity)
    throw new Error('Unexpected API request')
  }, true, null, newCredential)

  const credential = await ensure()
  assert.equal(credential.clientId, newCredential.clientId)
  assert.equal(location.searchParams.get('client'), newCredential.clientId)
  const retrieved = await apiService.getPublicActivity(credential.clientId)
  assert.deepEqual(JSON.parse(JSON.stringify(retrieved)), activity)
  assert.equal(requests.at(-1).url.endsWith(`/public/activity/${newCredential.clientId}`), true)
  assert.equal(requests.at(-1).options.headers['X-Client-Token'], newCredential.token)
})

test('linked app reports bridge failures immediately with a sanitized diagnostic', async () => {
  const { ensure } = webClient(async () => denied(), true, null, {
    type: 'tracking-threats:client-credential-error',
    code: 'CREDENTIAL_UNAVAILABLE',
  })
  await assert.rejects(ensure(), /extension could not verify this browser/i)
})

test('Dashboard, Live Monitor, and History consume the public activity state', () => {
  const provider = readFileSync(new URL('../../src/context/ThreatProvider.jsx', import.meta.url), 'utf8')
  const dashboard = readFileSync(new URL('../../src/pages/Dashboard.jsx', import.meta.url), 'utf8')
  const liveMonitor = readFileSync(new URL('../../src/pages/LiveMonitor.jsx', import.meta.url), 'utf8')
  const history = readFileSync(new URL('../../src/pages/ScanHistory.jsx', import.meta.url), 'utf8')

  assert.match(provider, /setScanHistory\(nextScans\)/)
  assert.match(provider, /setLiveFeed\(nextScans\.map\(toPublicLiveEvent\)\)/)
  assert.match(provider, /setLiveScanCount\(nextScans\.length\)/)
  assert.match(dashboard, /scanHistory/)
  assert.match(liveMonitor, /liveFeed/)
  assert.match(history, /scanHistory/)
})

test('web client keeps its identity during server failures', async () => {
  const { ensure, storage } = webClient(async () => Response.json({ error: 'Unavailable' }, { status: 503 }))
  await assert.rejects(ensure(), /Unavailable/)
  assert.equal(JSON.parse(storage.get('threattrack:client-credential')).clientId, oldCredential.clientId)
})

test('web client retains a valid identity without registering another one', async () => {
  const { ensure } = webClient(async (url) => {
    assert.equal(url.endsWith(`/public/clients/${oldCredential.clientId}`), true)
    return Response.json({ clientId: oldCredential.clientId })
  })
  assert.equal((await ensure()).clientId, oldCredential.clientId)
})
