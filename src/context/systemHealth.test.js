import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { resolveRoute } from '../routing.js'
import { createRefreshPolling } from './refreshPolling.js'
import {
  createSystemHealthPolling,
  getSystemStatusPresentation,
  readSystemHealthStatus,
  SYSTEM_HEALTH_POLL_INTERVAL_MS,
} from './systemHealth.js'

const flushPromises = () => new Promise((resolve) => setTimeout(resolve, 0))

function createFakeDocument() {
  const listeners = new Set()
  return {
    visibilityState: 'visible',
    addEventListener(name, listener) {
      if (name === 'visibilitychange') listeners.add(listener)
    },
    removeEventListener(name, listener) {
      if (name === 'visibilitychange') listeners.delete(listener)
    },
    dispatchVisibilityChange() {
      for (const listener of listeners) listener()
    },
  }
}

function createFakeTimers() {
  const intervals = new Map()
  let nextId = 1
  return {
    intervals,
    setIntervalFn(callback, intervalMs) {
      const id = nextId++
      intervals.set(id, { callback, intervalMs })
      return id
    },
    clearIntervalFn(id) {
      intervals.delete(id)
    },
    tick() {
      for (const interval of [...intervals.values()]) interval.callback()
    },
  }
}

test('successful health response marks the system active only for systemActive true', async () => {
  let receivedSignal
  const status = await readSystemHealthStatus(async ({ signal }) => {
    receivedSignal = signal
    return { ok: true, systemActive: true }
  })

  assert.equal(status, 'active')
  assert(receivedSignal instanceof AbortSignal)
  assert.equal(receivedSignal.aborted, false)
  assert.equal(await readSystemHealthStatus(async () => ({ ok: true })), 'unavailable')
  assert.equal(await readSystemHealthStatus(async () => ({ ok: true, systemActive: false })), 'unavailable')
})

test('HTTP 503, network failure, and request timeout are unavailable', async () => {
  const unavailableResponse = await readSystemHealthStatus(async () => {
    throw Object.assign(new Error('Service unavailable'), { status: 503 })
  })
  const networkFailure = await readSystemHealthStatus(async () => {
    throw new TypeError('Failed to fetch')
  })
  const timeout = await readSystemHealthStatus(async () => {
    throw Object.assign(new Error('Request timed out'), { name: 'TimeoutError' })
  })

  assert.equal(unavailableResponse, 'unavailable')
  assert.equal(networkFailure, 'unavailable')
  assert.equal(timeout, 'unavailable')
})

test('successful health polling updates the shared status to Active', async () => {
  const documentRef = createFakeDocument()
  const timers = createFakeTimers()
  const statuses = []
  const stop = createSystemHealthPolling({
    documentRef,
    getHealth: async () => ({ ok: true, systemActive: true }),
    onStatus: (status) => statuses.push(status),
    ...timers,
  })

  await flushPromises()
  assert.deepEqual(statuses, ['active'])
  stop()
})

test('failed health polling updates the shared status to Unavailable', async () => {
  const documentRef = createFakeDocument()
  const timers = createFakeTimers()
  const statuses = []
  const stop = createSystemHealthPolling({
    documentRef,
    getHealth: async () => { throw new TypeError('Network failure') },
    onStatus: (status) => statuses.push(status),
    ...timers,
  })

  await flushPromises()
  assert.deepEqual(statuses, ['unavailable'])
  stop()
})

test('direct Admin route still runs independent health check while heavy polling is paused', async () => {
  assert.equal(resolveRoute('https://tracking-threats.test/admin').page, 'admin')
  const documentRef = createFakeDocument()
  const timers = createFakeTimers()
  let healthCalls = 0
  let heavyCalls = 0
  let status = 'checking'
  const heavyPolling = createRefreshPolling({
    documentRef,
    refresh: async () => { heavyCalls += 1 },
    onError: () => {},
    initiallyPaused: true,
    ...timers,
  })

  const stopHealthPolling = createSystemHealthPolling({
    documentRef,
    getHealth: async () => {
      healthCalls += 1
      return { systemActive: true }
    },
    onStatus: (nextStatus) => { status = nextStatus },
    ...timers,
  })
  heavyPolling.start()
  await flushPromises()

  assert.equal(healthCalls, 1)
  assert.equal(heavyCalls, 0)
  assert.equal(status, 'active')
  assert.equal(timers.intervals.size, 1)

  heavyPolling.stop()
  stopHealthPolling()
})

test('health polling pauses when hidden and immediately refreshes once when visible', async () => {
  const documentRef = createFakeDocument()
  const timers = createFakeTimers()
  const statuses = []
  let calls = 0
  const stop = createSystemHealthPolling({
    documentRef,
    getHealth: async () => {
      calls += 1
      return { systemActive: calls === 1 }
    },
    onStatus: (status) => statuses.push(status),
    ...timers,
  })

  await flushPromises()
  assert.equal(calls, 1)
  assert.deepEqual(statuses, ['active'])
  assert.equal(timers.intervals.size, 1)
  assert.equal([...timers.intervals.values()][0].intervalMs, SYSTEM_HEALTH_POLL_INTERVAL_MS)

  documentRef.visibilityState = 'hidden'
  documentRef.dispatchVisibilityChange()
  assert.equal(timers.intervals.size, 0)
  timers.tick()
  await flushPromises()
  assert.equal(calls, 1)

  documentRef.visibilityState = 'visible'
  documentRef.dispatchVisibilityChange()
  await flushPromises()
  assert.equal(calls, 2)
  assert.deepEqual(statuses, ['active', 'unavailable'])
  assert.equal(timers.intervals.size, 1)

  stop()
  assert.equal(timers.intervals.size, 0)
})

test('health interval ticks reuse the in-flight request', async () => {
  const documentRef = createFakeDocument()
  const timers = createFakeTimers()
  let calls = 0
  let resolveHealth
  const healthRequest = new Promise((resolve) => { resolveHealth = resolve })
  const stop = createSystemHealthPolling({
    documentRef,
    getHealth: () => {
      calls += 1
      return healthRequest
    },
    onStatus: () => {},
    ...timers,
  })

  await flushPromises()
  timers.tick()
  timers.tick()
  await flushPromises()
  assert.equal(calls, 1)

  resolveHealth({ systemActive: true })
  await flushPromises()
  timers.tick()
  await flushPromises()
  assert.equal(calls, 2)
  stop()
})

test('health request stays shared if the polling effect restarts while it is in flight', async () => {
  const documentRef = createFakeDocument()
  const timers = createFakeTimers()
  let calls = 0
  let resolveHealth
  const healthRequest = new Promise((resolve) => { resolveHealth = resolve })
  const firstStop = createSystemHealthPolling({
    documentRef,
    getHealth: () => {
      calls += 1
      return healthRequest
    },
    onStatus: () => {},
    ...timers,
  })
  await flushPromises()
  firstStop()

  const statuses = []
  const secondStop = createSystemHealthPolling({
    documentRef,
    getHealth: () => {
      calls += 1
      return healthRequest
    },
    onStatus: (status) => statuses.push(status),
    ...timers,
  })
  await flushPromises()
  assert.equal(calls, 1)

  resolveHealth({ systemActive: true })
  await flushPromises()
  assert.deepEqual(statuses, ['active'])
  secondStop()
})

test('stopping a health poller prevents its in-flight response from updating status', async () => {
  const documentRef = createFakeDocument()
  const timers = createFakeTimers()
  const statuses = []
  let resolveHealth
  const healthRequest = new Promise((resolve) => { resolveHealth = resolve })
  const stop = createSystemHealthPolling({
    documentRef,
    getHealth: () => healthRequest,
    onStatus: (status) => statuses.push(status),
    ...timers,
  })

  await flushPromises()
  stop()
  resolveHealth({ systemActive: true })
  await flushPromises()

  assert.deepEqual(statuses, [])
  assert.equal(timers.intervals.size, 0)
})

test('Admin shell and User Dashboard render the same shared health status labels', () => {
  const layout = readFileSync(new URL('../components/Layout.jsx', import.meta.url), 'utf8')
  const dashboard = readFileSync(new URL('../pages/Dashboard.jsx', import.meta.url), 'utf8')
  const app = readFileSync(new URL('../App.jsx', import.meta.url), 'utf8')

  assert.match(layout, /getSystemStatusPresentation\(systemStatus\)/)
  assert.match(dashboard, /getSystemStatusPresentation\(systemStatus\)/)
  assert.match(app, /pauseAutoRefresh=\{activePage === 'admin'\}/)
  assert.deepEqual(
    ['checking', 'active', 'unavailable'].map((status) => getSystemStatusPresentation(status).label),
    ['Checking', 'Active', 'Unavailable'],
  )
})
