import { AnimatePresence, motion } from 'framer-motion'
import {
  Activity,
  BellRing,
  ChevronDown,
  Clipboard,
  Eye,
  FileText,
  History,
  Mail,
  MailCheck,
  Pause,
  Play,
  Radio,
  Router,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Volume2,
  X,
} from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Panel } from '../components/Panel'
import { RiskBadge } from '../components/RiskBadge'
import { useThreats } from '../hooks/useThreats'

const formatTime = (date) =>
  new Intl.DateTimeFormat(undefined, {
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(date))

const activityIcons = {
  Email: Mail,
  File: FileText,
  Message: MailCheck,
  Network: Router,
  URL: Activity,
}

const isHighRisk = (event) =>
  ['Dangerous', 'Blocked', 'Suspicious'].includes(event.status) ||
  ['Dangerous', 'Suspicious'].includes(event.riskStatus)

const getRecentWindow = (events, minutes) => {
  const cutoff = Date.now() - minutes * 60 * 1000
  return events.filter((event) => new Date(event.timestamp).getTime() >= cutoff)
}

const statusTone = {
  Safe: 'bg-emerald-500',
  Suspicious: 'bg-amber-500',
  Dangerous: 'bg-rose-500',
  Blocked: 'bg-rose-500',
}

export function LiveMonitor({ onNavigate }) {
  const {
    liveFeed,
    liveScanCount,
    systemActive,
    systemLogs,
  } = useThreats()
  const [showSystemLogs, setShowSystemLogs] = useState(false)
  const [isPaused, setIsPaused] = useState(false)
  const [pausedFeed, setPausedFeed] = useState([])
  const [autoScroll, setAutoScroll] = useState(true)
  const [soundAlert, setSoundAlert] = useState(false)
  const [desktopAlerts, setDesktopAlerts] = useState(false)
  const [timelineWindow, setTimelineWindow] = useState(15)
  const [selectedEventId, setSelectedEventId] = useState(null)
  const [copiedEventId, setCopiedEventId] = useState(null)
  const latestDangerousId = useRef(null)
  const feedEndRef = useRef(null)
  const visibleFeed = isPaused ? pausedFeed : liveFeed

  useEffect(() => {
    if (autoScroll && !isPaused) {
      feedEndRef.current?.scrollIntoView({ block: 'end', behavior: 'smooth' })
    }
  }, [autoScroll, isPaused, visibleFeed.length])

  useEffect(() => {
    const latestDangerous = liveFeed.find((event) => event.status === 'Blocked')
    if (!latestDangerous || latestDangerous.id === latestDangerousId.current) return

    latestDangerousId.current = latestDangerous.id
    if (soundAlert) {
      const audio = new Audio(
        'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAESsAACJWAAACABAAZGF0YQAAAAA=',
      )
      audio.play().catch(() => {})
    }
    if (desktopAlerts && Notification.permission === 'granted') {
      new Notification('Tracking Threats blocked a dangerous item', {
        body: latestDangerous.target,
      })
    }
  }, [desktopAlerts, liveFeed, soundAlert])

  const selectedEvent =
    visibleFeed.find((event) => event.id === selectedEventId) ??
    null
  const recentWindowEvents = getRecentWindow(visibleFeed, timelineWindow)
  const timelineCounts = {
    Safe: recentWindowEvents.filter((event) => event.status === 'Safe').length,
    Suspicious: recentWindowEvents.filter((event) => event.status === 'Suspicious').length,
    Dangerous: recentWindowEvents.filter((event) => event.status === 'Blocked').length,
  }
  const maxTimelineCount = Math.max(1, ...Object.values(timelineCounts))
  const dangerousCount = visibleFeed.filter((event) => event.status === 'Blocked').length
  const latestBlocked = visibleFeed.find((event) => event.status === 'Blocked')
  const highRiskCount = visibleFeed.filter(isHighRisk).length
  const scanRate = getRecentWindow(visibleFeed, 5).length

  const requestDesktopAlerts = async () => {
    if (!('Notification' in window)) return
    const permission =
      Notification.permission === 'default'
        ? await Notification.requestPermission()
        : Notification.permission
    setDesktopAlerts(permission === 'granted')
  }

  const togglePause = () => {
    if (isPaused) {
      setIsPaused(false)
      return
    }

    setPausedFeed(liveFeed)
    setIsPaused(true)
  }

  const copyTarget = async (event) => {
    await navigator.clipboard.writeText(event.target)
    setCopiedEventId(event.id)
    window.setTimeout(() => setCopiedEventId(null), 1200)
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-sm font-medium text-teal-700 dark:text-teal-300">Live Monitor</p>
          <h1 className="text-2xl font-semibold">Real-time threat activity</h1>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-slate-700 transition hover:border-teal-300 hover:text-teal-700 dark:border-slate-800 dark:text-slate-200 dark:hover:border-teal-500 dark:hover:text-teal-300"
            type="button"
            onClick={togglePause}
          >
            {isPaused ? <Play size={16} /> : <Pause size={16} />}
            {isPaused ? 'Resume' : 'Pause'}
          </button>
          <button
            className={`inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-semibold transition ${
              soundAlert
                ? 'border-amber-300 bg-amber-50 text-amber-800 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200'
                : 'border-slate-200 text-slate-700 dark:border-slate-800 dark:text-slate-200'
            }`}
            type="button"
            onClick={() => setSoundAlert((current) => !current)}
          >
            <Volume2 size={16} />
            Sound
          </button>
          <button
            className={`inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-semibold transition ${
              autoScroll
                ? 'border-teal-300 bg-teal-50 text-teal-800 dark:border-teal-700 dark:bg-teal-950 dark:text-teal-200'
                : 'border-slate-200 text-slate-700 dark:border-slate-800 dark:text-slate-200'
            }`}
            type="button"
            onClick={() => setAutoScroll((current) => !current)}
          >
            <SlidersHorizontal size={16} />
            Auto-scroll
          </button>
        </div>
      </div>

      <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <motion.div
          animate={{
            boxShadow: systemActive
              ? [
                  '0 0 0 rgba(16,185,129,0)',
                  '0 0 24px rgba(16,185,129,0.18)',
                  '0 0 0 rgba(16,185,129,0)',
                ]
              : '0 0 0 rgba(16,185,129,0)',
          }}
          transition={{ duration: 2.2, repeat: Infinity, ease: 'easeInOut' }}
          className="rounded-lg border border-emerald-500/25 bg-emerald-500/10 p-4"
        >
          <div className="flex items-center gap-2 text-sm font-semibold text-emerald-700 dark:text-emerald-300">
            <span className="relative flex h-3 w-3 items-center justify-center">
              {systemActive && (
                <span className="absolute h-3 w-3 animate-ping rounded-full bg-emerald-400 opacity-75" />
              )}
              <span className="relative h-2.5 w-2.5 rounded-full bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,0.95)]" />
            </span>
            {systemActive ? 'System Active' : 'System Idle'}
          </div>
          <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
            Local backend is collecting live activity.
          </p>
        </motion.div>

        <div className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
          <p className="text-sm text-slate-500 dark:text-slate-400">Live scan count</p>
          <p className="mt-1 text-3xl font-semibold text-slate-950 dark:text-white">
            {liveScanCount}
          </p>
          <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
            {scanRate} scans in the last 5 minutes
          </p>
        </div>

        <div className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
          <p className="text-sm text-slate-500 dark:text-slate-400">Current risk</p>
          <p className="mt-1 text-3xl font-semibold text-slate-950 dark:text-white">
            {dangerousCount > 0 ? 'High' : highRiskCount > 0 ? 'Elevated' : 'Low'}
          </p>
          <p className="mt-2 truncate text-sm text-slate-500 dark:text-slate-400">
            {latestBlocked ? latestBlocked.target : 'No blocked threat in live feed'}
          </p>
        </div>

        <div className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-sm text-slate-500 dark:text-slate-400">Dangerous alerts</p>
              <p className="mt-1 text-3xl font-semibold text-slate-950 dark:text-white">
                {dangerousCount}
              </p>
            </div>
            <BellRing className="text-rose-500" size={26} />
          </div>
          <button
            className="mt-3 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-slate-100 px-3 py-2 text-sm font-semibold text-slate-800 transition hover:bg-teal-100 hover:text-teal-800 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-teal-950 dark:hover:text-teal-200"
            type="button"
            onClick={requestDesktopAlerts}
          >
            <Volume2 size={15} />
            Desktop alerts
          </button>
        </div>
      </section>

      <section className="grid gap-4">
        <Panel>
          <div className="mb-4 flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium text-teal-700 dark:text-teal-300">
                Severity timeline
              </p>
              <h2 className="mt-1 text-lg font-semibold">Recent activity window</h2>
            </div>
            <select
              className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none dark:border-slate-800 dark:bg-slate-950"
              value={timelineWindow}
              onChange={(event) => setTimelineWindow(Number(event.target.value))}
            >
              <option value={5}>5 min</option>
              <option value={15}>15 min</option>
              <option value={60}>60 min</option>
            </select>
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            {Object.entries(timelineCounts).map(([status, count]) => (
              <div key={status} className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
                <div className="mb-2 flex items-center justify-between text-sm">
                  <span className="font-medium">{status}</span>
                  <span className="text-slate-500 dark:text-slate-400">{count}</span>
                </div>
                <div className="h-24 overflow-hidden rounded-lg bg-slate-100 dark:bg-slate-950">
                  <div className="flex h-full items-end justify-center p-3">
                    <span
                      className={`w-full rounded-t-md ${statusTone[status]}`}
                      style={{ height: `${Math.max(8, (count / maxTimelineCount) * 100)}%` }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </section>

      <Panel>
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400">
            <motion.span
              animate={isPaused ? {} : { scale: [1, 1.18, 1], opacity: [0.75, 1, 0.75] }}
              transition={{ duration: 1.4, repeat: Infinity }}
              className="grid h-8 w-8 place-items-center rounded-lg bg-teal-500/15 text-teal-600 dark:text-teal-300"
            >
              <Radio size={17} />
            </motion.span>
            {isPaused ? 'Live feed paused' : 'Browser link monitoring is ready'}
          </div>
          <div className="inline-flex items-center gap-2 rounded-full border border-slate-200 px-3 py-2 text-xs font-medium text-slate-500 dark:border-slate-800 dark:text-slate-400">
            <ShieldCheck size={15} className="text-teal-500" />
            {visibleFeed.length}/50 items
          </div>
        </div>

        {visibleFeed.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-300 p-6 text-center text-sm text-slate-500 dark:border-slate-800 dark:text-slate-400">
            Waiting for the first browser, email, file, URL, or manual scan...
          </div>
        ) : (
          <div className="max-h-[620px] space-y-3 overflow-auto pr-1">
            {visibleFeed.slice(0, 12).map((event, index) => {
              const Icon = activityIcons[event.activityType] ?? Activity

              return (
                <motion.article
                  key={event.id}
                  initial={{ opacity: 0, x: -12 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: Math.min(index * 0.015, 0.16) }}
                  className={`rounded-lg border p-4 ${
                    event.status === 'Blocked'
                      ? 'border-rose-500/40 bg-rose-500/5'
                      : 'border-slate-200 dark:border-slate-800'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <button
                      className="flex min-w-0 flex-1 gap-3 text-left"
                      type="button"
                      onClick={() => setSelectedEventId(event.id)}
                    >
                      <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-200">
                        <Icon size={18} />
                      </span>
                      <div className="min-w-0">
                        <p className="text-sm font-semibold">{event.title}</p>
                        {event.activityType === 'Network' && (
                          <p className="mt-1 text-sm font-medium text-slate-700 dark:text-slate-200">
                            Domain: {event.domain}
                          </p>
                        )}
                        <p className="mt-1 truncate text-sm text-slate-500 dark:text-slate-400">
                          {event.target}
                        </p>
                        <p className="mt-2 text-xs text-slate-400">
                          {event.source} • Safety score {event.score}/100 •{' '}
                          {formatTime(event.timestamp)}
                        </p>
                      </div>
                    </button>
                    <div className="flex shrink-0 flex-col items-end gap-2">
                      <RiskBadge risk={event.status} />
                      <button
                        className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-semibold text-teal-700 hover:bg-teal-50 dark:text-teal-300 dark:hover:bg-teal-950"
                        type="button"
                        onClick={() => setSelectedEventId(event.id)}
                      >
                        <Eye size={14} />
                        Details
                      </button>
                    </div>
                  </div>
                </motion.article>
              )
            })}
            <div ref={feedEndRef} />
          </div>
        )}
      </Panel>

      <Panel>
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold">System logs</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">Latest backend events</p>
          </div>
          <button
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm font-medium text-slate-700 transition hover:border-teal-300 hover:text-teal-700 dark:border-slate-800 dark:text-slate-200 dark:hover:border-teal-500 dark:hover:text-teal-300"
            type="button"
            onClick={() => setShowSystemLogs((current) => !current)}
          >
            {showSystemLogs ? 'Hide logs' : `Show logs (${systemLogs.length})`}
            <ChevronDown
              size={16}
              className={`transition-transform ${showSystemLogs ? 'rotate-180' : ''}`}
            />
          </button>
        </div>
        {showSystemLogs &&
          (systemLogs.length === 0 ? (
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Waiting for backend scan logs...
            </p>
          ) : (
            <div className="space-y-2">
              {systemLogs.slice(0, 6).map((log) => (
                <div
                  key={log.id}
                  className="min-w-0 rounded-lg border border-slate-200 p-3 text-sm dark:border-slate-800"
                >
                  <div className="flex min-w-0 items-center justify-between gap-3">
                    <p className="min-w-0 truncate font-medium">{log.event}</p>
                    <span className="shrink-0 text-xs text-slate-400">
                      {formatTime(log.timestamp)}
                    </span>
                  </div>
                  <p className="mt-1 max-w-full break-words text-slate-500 dark:text-slate-400">
                    {log.message}
                  </p>
                </div>
              ))}
            </div>
          ))}
      </Panel>

      <AnimatePresence>
        {selectedEvent && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-slate-950/55 px-4 py-5 backdrop-blur-sm"
            onClick={() => setSelectedEventId(null)}
          >
            <motion.aside
              initial={{ x: 28, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: 28, opacity: 0 }}
              transition={{ duration: 0.18 }}
              className="ml-auto flex h-full w-full max-w-xl flex-col overflow-hidden rounded-lg border border-slate-200 bg-white shadow-2xl dark:border-slate-800 dark:bg-slate-900"
              onClick={(event) => event.stopPropagation()}
            >
              <div className="flex items-start justify-between gap-3 border-b border-slate-200 p-4 dark:border-slate-800">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-teal-700 dark:text-teal-300">
                    Event details
                  </p>
                  <h2 className="mt-1 truncate text-xl font-semibold">{selectedEvent.title}</h2>
                </div>
                <button
                  aria-label="Close details"
                  className="grid h-9 w-9 shrink-0 place-items-center rounded-lg text-slate-500 hover:bg-slate-100 hover:text-slate-900 dark:hover:bg-slate-800 dark:hover:text-white"
                  type="button"
                  onClick={() => setSelectedEventId(null)}
                >
                  <X size={19} />
                </button>
              </div>

              <div className="flex-1 space-y-4 overflow-auto p-4">
                <div className="flex items-start justify-between gap-3 rounded-lg border border-slate-200 p-3 dark:border-slate-800">
                  <div className="min-w-0">
                    <p className="break-all text-sm font-semibold">{selectedEvent.target}</p>
                    <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                      {selectedEvent.activityType} • {selectedEvent.source} •{' '}
                      {formatTime(selectedEvent.timestamp)}
                    </p>
                  </div>
                  <RiskBadge risk={selectedEvent.status} />
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
                    <p className="text-xs font-semibold uppercase text-slate-400">Safety score</p>
                    <p className="mt-1 text-2xl font-semibold">{selectedEvent.score}/100</p>
                  </div>
                  <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
                    <p className="text-xs font-semibold uppercase text-slate-400">Domain</p>
                    <p className="mt-1 truncate text-sm font-medium">
                      {selectedEvent.domain || 'Not available'}
                    </p>
                  </div>
                </div>

                <div>
                  <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold">
                    <ShieldAlert size={17} className="text-amber-500" />
                    Warning signs
                  </h3>
                  {selectedEvent.warningSigns?.length > 0 ? (
                    <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-300">
                      {selectedEvent.warningSigns.map((warning) => (
                        <li key={warning} className="rounded-lg bg-slate-100 p-2 dark:bg-slate-950">
                          {warning}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-sm text-slate-500 dark:text-slate-400">
                      No warning signs attached to this live event.
                    </p>
                  )}
                </div>

                <div>
                  <h3 className="mb-2 text-sm font-semibold">Detail</h3>
                  <p className="break-words rounded-lg bg-slate-100 p-3 text-sm text-slate-600 dark:bg-slate-950 dark:text-slate-300">
                    {selectedEvent.detail || selectedEvent.target}
                  </p>
                </div>
              </div>

              <div className="grid gap-2 border-t border-slate-200 p-4 dark:border-slate-800 sm:grid-cols-2">
                <button
                  className="inline-flex items-center justify-center gap-2 rounded-lg bg-slate-100 px-3 py-2 text-sm font-semibold text-slate-800 transition hover:bg-teal-100 hover:text-teal-800 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-teal-950 dark:hover:text-teal-200"
                  type="button"
                  onClick={() => copyTarget(selectedEvent)}
                >
                  <Clipboard size={16} />
                  {copiedEventId === selectedEvent.id ? 'Copied' : 'Copy target'}
                </button>
                <button
                  className="inline-flex items-center justify-center gap-2 rounded-lg bg-slate-100 px-3 py-2 text-sm font-semibold text-slate-800 transition hover:bg-teal-100 hover:text-teal-800 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-teal-950 dark:hover:text-teal-200"
                  type="button"
                  onClick={() => onNavigate('history')}
                >
                  <History size={16} />
                  View history
                </button>
                <button
                  className="inline-flex items-center justify-center gap-2 rounded-lg border border-rose-500/30 px-3 py-2 text-sm font-semibold text-rose-700 transition hover:bg-rose-50 dark:text-rose-300 dark:hover:bg-rose-950 sm:col-span-2"
                  type="button"
                  onClick={() => onNavigate('alerts')}
                >
                  <ShieldAlert size={16} />
                  Open in Alerts
                </button>
              </div>
            </motion.aside>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
