import { coordinateRefresh, createRefreshPolling } from './refreshPolling.js'

export const SYSTEM_HEALTH_POLL_INTERVAL_MS = 30_000
export const SYSTEM_HEALTH_REQUEST_TIMEOUT_MS = 8_000
const systemHealthInFlightRef = { current: null }

const systemStatusPresentations = {
  checking: {
    label: 'Checking',
    badge: 'border-amber-400 bg-amber-100 text-amber-800 dark:border-amber-700 dark:bg-amber-950/60 dark:text-amber-300',
    dot: 'bg-amber-400',
    panel: 'border-amber-300 bg-amber-100/80 text-amber-950 shadow-[0_16px_36px_rgba(217,119,6,0.1)] dark:border-amber-700 dark:bg-amber-950/35 dark:text-white',
    icon: 'bg-amber-500 text-white shadow-[0_14px_28px_rgba(217,119,6,0.2)]',
    text: 'text-amber-800 dark:text-amber-200',
  },
  active: {
    label: 'Active',
    badge: 'border-emerald-400 bg-emerald-100 text-emerald-700 dark:border-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300',
    dot: 'bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,0.95)]',
    panel: 'border-emerald-300 bg-emerald-100/80 text-emerald-950 shadow-[0_16px_36px_rgba(5,150,105,0.12)] dark:border-emerald-700 dark:bg-emerald-950/35 dark:text-white',
    icon: 'bg-emerald-500 text-white shadow-[0_14px_28px_rgba(5,150,105,0.25)]',
    text: 'text-emerald-800 dark:text-emerald-200',
  },
  unavailable: {
    label: 'Unavailable',
    badge: 'border-rose-400 bg-rose-100 text-rose-700 dark:border-rose-700 dark:bg-rose-950/60 dark:text-rose-300',
    dot: 'bg-rose-500',
    panel: 'border-rose-300 bg-rose-100/80 text-rose-950 shadow-[0_16px_36px_rgba(225,29,72,0.1)] dark:border-rose-700 dark:bg-rose-950/35 dark:text-white',
    icon: 'bg-rose-500 text-white shadow-[0_14px_28px_rgba(225,29,72,0.2)]',
    text: 'text-rose-800 dark:text-rose-200',
  },
}

export const getSystemStatusPresentation = (status) =>
  systemStatusPresentations[status] ?? systemStatusPresentations.checking

export async function readSystemHealthStatus(getHealth) {
  try {
    const response = await getHealth({
      signal: AbortSignal.timeout(SYSTEM_HEALTH_REQUEST_TIMEOUT_MS),
    })
    return response?.systemActive === true ? 'active' : 'unavailable'
  } catch {
    return 'unavailable'
  }
}

export function createSystemHealthPolling({
  documentRef,
  getHealth,
  onStatus,
  intervalMs = SYSTEM_HEALTH_POLL_INTERVAL_MS,
  setIntervalFn = setInterval,
  clearIntervalFn = clearInterval,
}) {
  let stopped = false

  const refresh = async () => {
    const status = await coordinateRefresh(
      () => readSystemHealthStatus(getHealth),
      systemHealthInFlightRef,
    )
    if (!stopped) onStatus(status)
  }

  const polling = createRefreshPolling({
    documentRef,
    refresh,
    onError: () => {
      if (!stopped) onStatus('unavailable')
    },
    intervalMs,
    setIntervalFn,
    clearIntervalFn,
  })

  const stop = polling.start()
  return () => {
    stopped = true
    stop()
  }
}
