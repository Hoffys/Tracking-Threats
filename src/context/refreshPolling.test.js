import assert from 'node:assert/strict'
import test from 'node:test'
import { coordinateRefresh, createRefreshPolling } from './refreshPolling.js'

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
    get listenerCount() {
      return listeners.size
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
      for (const interval of intervals.values()) interval.callback()
    },
  }
}

test('simultaneous action and polling refreshes share one in-flight request', async () => {
  let resolveRequest
  let calls = 0
  const request = new Promise((resolve) => { resolveRequest = resolve })
  const inFlightRef = { current: null }
  const refresh = () => {
    calls += 1
    return request
  }

  const actionRefresh = coordinateRefresh(refresh, inFlightRef)
  const pollingRefresh = coordinateRefresh(refresh, inFlightRef)
  assert.strictEqual(pollingRefresh, actionRefresh)
  await flushPromises()
  assert.equal(calls, 1)

  resolveRequest('updated')
  assert.deepEqual(await Promise.all([actionRefresh, pollingRefresh]), ['updated', 'updated'])
  assert.equal(inFlightRef.current, null)
})

test('failed shared refresh rejects for callers, clears the guard, and allows retry', async () => {
  let rejectRequest
  let calls = 0
  const request = new Promise((_, reject) => { rejectRequest = reject })
  const inFlightRef = { current: null }
  const refresh = () => {
    calls += 1
    return calls === 1 ? request : Promise.resolve('recovered')
  }

  const first = coordinateRefresh(refresh, inFlightRef)
  const second = coordinateRefresh(refresh, inFlightRef)
  assert.strictEqual(second, first)
  await flushPromises()
  rejectRequest(new Error('refresh failed'))
  const failed = await Promise.allSettled([first, second])
  assert.deepEqual(failed.map(({ status }) => status), ['rejected', 'rejected'])
  assert.equal(inFlightRef.current, null)

  assert.equal(await coordinateRefresh(refresh, inFlightRef), 'recovered')
  assert.equal(calls, 2)
})

test('polling stays paused on Admin and resumes with one interval after leaving Admin', async () => {
  const documentRef = createFakeDocument()
  const timers = createFakeTimers()
  let calls = 0
  const polling = createRefreshPolling({
    documentRef,
    refresh: async () => { calls += 1 },
    onError: (error) => { throw error },
    initiallyPaused: true,
    intervalMs: 30_000,
    ...timers,
  })

  polling.start()
  await flushPromises()
  assert.equal(calls, 0)
  assert.equal(timers.intervals.size, 0)

  polling.setPaused(false)
  await flushPromises()
  assert.equal(calls, 1)
  assert.deepEqual([...timers.intervals.values()].map(({ intervalMs }) => intervalMs), [30_000])

  polling.setPaused(true)
  assert.equal(timers.intervals.size, 0)
  polling.setPaused(false)
  await flushPromises()
  assert.equal(calls, 2)
  assert.equal(timers.intervals.size, 1)
  polling.stop()
  assert.equal(timers.intervals.size, 0)
  assert.equal(documentRef.listenerCount, 0)
})

test('polling pauses while hidden and refreshes once when the tab becomes visible', async () => {
  const documentRef = createFakeDocument()
  const timers = createFakeTimers()
  let calls = 0
  const polling = createRefreshPolling({
    documentRef,
    refresh: async () => { calls += 1 },
    onError: (error) => { throw error },
    intervalMs: 30_000,
    ...timers,
  })

  polling.start()
  await flushPromises()
  assert.equal(calls, 1)
  assert.equal(timers.intervals.size, 1)

  documentRef.visibilityState = 'hidden'
  documentRef.dispatchVisibilityChange()
  assert.equal(timers.intervals.size, 0)
  await flushPromises()
  assert.equal(calls, 1)

  documentRef.visibilityState = 'visible'
  documentRef.dispatchVisibilityChange()
  await flushPromises()
  assert.equal(calls, 2)
  assert.equal(timers.intervals.size, 1)
  polling.stop()
  assert.equal(timers.intervals.size, 0)
  assert.equal(documentRef.listenerCount, 0)
})

test('scheduled polling catches failed refreshes instead of leaking rejections', async () => {
  const documentRef = createFakeDocument()
  const timers = createFakeTimers()
  const failure = new Error('scheduled refresh failed')
  const errors = []
  const polling = createRefreshPolling({
    documentRef,
    refresh: () => Promise.reject(failure),
    onError: (error) => errors.push(error),
    intervalMs: 30_000,
    ...timers,
  })

  polling.start()
  await flushPromises()
  assert.deepEqual(errors, [failure])
  polling.stop()
})
