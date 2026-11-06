export function coordinateRefresh(refresh, inFlightRef) {
  if (inFlightRef.current) return inFlightRef.current

  let coordinatedPromise
  coordinatedPromise = Promise.resolve()
    .then(refresh)
    .finally(() => {
      if (inFlightRef.current === coordinatedPromise) inFlightRef.current = null
    })
  inFlightRef.current = coordinatedPromise
  return coordinatedPromise
}

export function createRefreshPolling({
  documentRef,
  refresh,
  onError,
  intervalMs = 30_000,
  initiallyPaused = false,
  setIntervalFn = setInterval,
  clearIntervalFn = clearInterval,
}) {
  let active = false
  let paused = initiallyPaused
  let intervalId = null

  const poll = () => {
    if (!active || paused || documentRef.visibilityState === 'hidden') return
    void Promise.resolve()
      .then(() => {
        if (!active || paused || documentRef.visibilityState === 'hidden') return undefined
        return refresh()
      })
      .catch((error) => onError(error))
  }

  const stopInterval = () => {
    if (intervalId === null) return
    clearIntervalFn(intervalId)
    intervalId = null
  }

  const sync = () => {
    if (!active) return
    if (paused || documentRef.visibilityState === 'hidden') {
      stopInterval()
      return
    }
    if (intervalId !== null) return

    poll()
    intervalId = setIntervalFn(poll, intervalMs)
  }

  const stop = () => {
    if (!active) return
    active = false
    stopInterval()
    documentRef.removeEventListener('visibilitychange', sync)
  }

  return {
    start() {
      if (!active) {
        active = true
        documentRef.addEventListener('visibilitychange', sync)
        sync()
      }
      return stop
    },
    setPaused(nextPaused) {
      paused = nextPaused
      sync()
    },
    stop,
  }
}
