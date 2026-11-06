import assert from 'node:assert/strict'
import test from 'node:test'
import {
  ANNOUNCEMENT_POLL_INTERVAL_MS,
  createAnnouncementPolling,
  createAnnouncementRefresh,
  mergeReadAnnouncementIds,
} from './announcementPolling.js'

const deferred = () => {
  let resolve
  let reject
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

const createDocument = () => {
  const listeners = new Set()
  return {
    visibilityState: 'visible',
    addEventListener: (name, listener) => { if (name === 'visibilitychange') listeners.add(listener) },
    removeEventListener: (name, listener) => { if (name === 'visibilitychange') listeners.delete(listener) },
    dispatchVisibilityChange() { listeners.forEach((listener) => listener()) },
    listenerCount: () => listeners.size,
  }
}

test('bell-open refresh shares in-flight work and removes duplicate announcements', async () => {
  const request = deferred()
  let fetchCount = 0
  let received = []
  const refresh = createAnnouncementRefresh({
    fetchAnnouncements: () => { fetchCount += 1; return request.promise },
    onSuccess: (_payload, announcements) => { received = announcements },
  })

  const fromBellOpen = refresh()
  const concurrentPoll = refresh()
  assert.equal(concurrentPoll, fromBellOpen)
  await Promise.resolve()
  assert.equal(fetchCount, 1)
  request.resolve({ announcements: [{ id: 'new' }, { id: 'new' }] })
  await fromBellOpen
  assert.deepEqual(received, [{ id: 'new' }])
})

test('read announcement IDs remain deduplicated and bounded', () => {
  const current = Array.from({ length: 100 }, (_, index) => String(index))
  const next = mergeReadAnnouncementIds(current, [{ id: 99 }, { id: 'new' }, { id: 'new' }])
  assert.equal(next.length, 100)
  assert.equal(next.includes('99'), true)
  assert.equal(next.includes('new'), true)
  assert.equal(next.filter((id) => id === 'new').length, 1)
})

test('failed refresh preserves the last successful announcement list', async () => {
  let visibleAnnouncements = [{ id: 'existing', title: 'Existing' }]
  let attempts = 0
  const refresh = createAnnouncementRefresh({
    fetchAnnouncements: async () => {
      attempts += 1
      if (attempts === 1) return { announcements: visibleAnnouncements }
      throw new Error('offline')
    },
    onSuccess: (_payload, announcements) => { visibleAnnouncements = announcements },
  })

  await refresh()
  await refresh()
  assert.deepEqual(visibleAnnouncements, [{ id: 'existing', title: 'Existing' }])
})

test('polls every 30 seconds while visible, pauses while hidden, and refreshes on resume', () => {
  const documentRef = createDocument()
  const intervals = new Map()
  const createdIntervalIds = []
  const clearedIntervalIds = []
  let nextIntervalId = 0
  let refreshCount = 0
  const polling = createAnnouncementPolling({
    refresh: () => { refreshCount += 1 },
    documentRef,
    setIntervalFn: (callback, delay) => {
      assert.equal(delay, ANNOUNCEMENT_POLL_INTERVAL_MS)
      const id = ++nextIntervalId
      createdIntervalIds.push(id)
      intervals.set(id, { callback, delay })
      return id
    },
    clearIntervalFn: (id) => {
      clearedIntervalIds.push(id)
      intervals.delete(id)
    },
  })

  polling.start()
  assert.equal(refreshCount, 1)
  assert.equal(intervals.size, 1)
  const firstInterval = intervals.get(1)
  assert.equal(firstInterval.delay, 30_000)

  documentRef.dispatchVisibilityChange()
  documentRef.dispatchVisibilityChange()
  assert.equal(refreshCount, 1)
  assert.equal(intervals.size, 1)
  assert.deepEqual(createdIntervalIds, [1])

  firstInterval.callback()
  assert.equal(refreshCount, 2)
  firstInterval.callback()
  assert.equal(refreshCount, 3)

  documentRef.visibilityState = 'hidden'
  documentRef.dispatchVisibilityChange()
  assert.equal(intervals.size, 0)
  assert.deepEqual(clearedIntervalIds, [1])
  const pausedRefreshCount = refreshCount
  firstInterval.callback()
  assert.equal(refreshCount, pausedRefreshCount)

  documentRef.visibilityState = 'visible'
  documentRef.dispatchVisibilityChange()
  assert.equal(refreshCount, pausedRefreshCount + 1)
  assert.equal(intervals.size, 1)
  assert.deepEqual(createdIntervalIds, [1, 2])
  const resumedInterval = intervals.values().next().value
  assert.equal(resumedInterval.delay, 30_000)
  documentRef.dispatchVisibilityChange()
  assert.equal(refreshCount, pausedRefreshCount + 1)
  assert.equal(intervals.size, 1)
  resumedInterval.callback()
  resumedInterval.callback()
  assert.equal(refreshCount, pausedRefreshCount + 3)

  polling.stop()
  assert.equal(intervals.size, 0)
  assert.deepEqual(clearedIntervalIds, [1, 2])
  assert.equal(documentRef.listenerCount(), 0)
  resumedInterval.callback()
  assert.equal(refreshCount, pausedRefreshCount + 3)
})

test('initially hidden polling starts once when visible and ignores repeated visibility events', () => {
  const documentRef = createDocument()
  documentRef.visibilityState = 'hidden'
  let refreshCount = 0
  let intervalCount = 0
  const polling = createAnnouncementPolling({
    refresh: () => { refreshCount += 1 },
    documentRef,
    setIntervalFn: () => { intervalCount += 1; return intervalCount },
    clearIntervalFn: () => { intervalCount -= 1 },
  })

  polling.start()
  assert.equal(refreshCount, 0)
  assert.equal(intervalCount, 0)
  documentRef.visibilityState = 'visible'
  documentRef.dispatchVisibilityChange()
  assert.equal(refreshCount, 1)
  assert.equal(intervalCount, 1)
  documentRef.dispatchVisibilityChange()
  assert.equal(refreshCount, 1)
  assert.equal(intervalCount, 1)
  polling.stop()
  assert.equal(documentRef.listenerCount(), 0)
  assert.equal(intervalCount, 0)
})
