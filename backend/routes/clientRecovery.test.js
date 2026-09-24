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
    URL, fetch, importScripts() {},
    TRACKING_THREATS_CONFIG: { API_BASE_URL: 'https://api.example', APP_URL: 'https://app.example' },
    chrome: { storage: { local: {
      get: async () => ({ ...stored }),
      set: async (values) => Object.assign(stored, values),
    } } },
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

function webClient(fetch, linked = false) {
  const storage = new Map([['threattrack:client-credential', JSON.stringify(oldCredential)]])
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
        data: { type: 'tracking-threats:client-credential', requestedClientId: message.clientId, ...newCredential },
      })
    }),
  }
  const sandbox = {
    URL, URLSearchParams, window, fetch,
    localStorage: { getItem: (key) => storage.get(key), setItem: (key, value) => storage.set(key, value) },
  }
  const source = readFileSync(new URL('../../src/services/api.js', import.meta.url), 'utf8')
    .replace('import.meta.env.VITE_API_BASE_URL', 'undefined')
    .replaceAll('export const ', 'const ')
  vm.runInNewContext(`${source}\nglobalThis.ensure = ensureClientCredential`, sandbox)
  return { ensure: sandbox.ensure, storage, location }
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
