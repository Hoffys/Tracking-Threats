export const ANNOUNCEMENT_POLL_INTERVAL_MS = 30_000

export function uniqueAnnouncements(announcements) {
  if (!Array.isArray(announcements)) return []
  const seen = new Set()
  return announcements.filter((announcement) => {
    const id = String(announcement?.id ?? '')
    if (!id || seen.has(id)) return false
    seen.add(id)
    return true
  })
}

export function mergeReadAnnouncementIds(currentIds, announcements) {
  return Array.from(new Set([
    ...currentIds,
    ...announcements.map((announcement) => String(announcement.id)),
  ])).slice(-100)
}

export function createAnnouncementRefresh({ fetchAnnouncements, onStart, onSuccess, onError, onSettled }) {
  let inFlight = null

  const refresh = () => {
    if (inFlight) return inFlight
    onStart?.()
    inFlight = Promise.resolve()
      .then(fetchAnnouncements)
      .then((payload) => {
        const announcements = uniqueAnnouncements(payload?.announcements)
        onSuccess?.(payload, announcements)
        return announcements
      })
      .catch((error) => {
        onError?.(error)
        return null
      })
      .finally(() => {
        inFlight = null
        onSettled?.()
      })
    return inFlight
  }

  return refresh
}

export function createAnnouncementPolling({
  refresh,
  documentRef,
  intervalMs = ANNOUNCEMENT_POLL_INTERVAL_MS,
  setIntervalFn = setInterval,
  clearIntervalFn = clearInterval,
}) {
  let intervalId = null
  let started = false

  const stopInterval = () => {
    if (intervalId === null) return
    clearIntervalFn(intervalId)
    intervalId = null
  }

  const poll = () => {
    if (!started || documentRef.visibilityState === 'hidden') return
    Promise.resolve(refresh()).catch(() => {})
  }

  const sync = () => {
    if (!started) return
    if (documentRef.visibilityState === 'hidden') {
      stopInterval()
      return
    }
    if (intervalId !== null) return
    const scheduledIntervalId = setIntervalFn(() => {
      if (intervalId !== scheduledIntervalId) return
      poll()
    }, intervalMs)
    intervalId = scheduledIntervalId
    poll()
  }

  const start = () => {
    if (started) return
    started = true
    documentRef.addEventListener('visibilitychange', sync)
    sync()
  }

  const stop = () => {
    if (!started) return
    started = false
    stopInterval()
    documentRef.removeEventListener('visibilitychange', sync)
  }

  return { start, stop }
}
