import { motion } from 'framer-motion'
import { Activity, Mail, Radio, Router, ShieldCheck } from 'lucide-react'
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
  Network: Router,
  URL: Activity,
}

export function LiveMonitor() {
  const { liveFeed, liveScanCount, systemActive, systemLogs } = useThreats()

  return (
    <div className="space-y-5">
      <div>
        <p className="text-sm font-medium text-teal-700 dark:text-teal-300">Live Monitor</p>
        <h1 className="text-2xl font-semibold">Real-time threat activity</h1>
      </div>

      <section className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-lg border border-emerald-500/25 bg-emerald-500/10 p-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-emerald-700 dark:text-emerald-300">
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
            {systemActive ? 'System Active' : 'System Idle'}
          </div>
          <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
            Browser, manual URL, message, and email scans are collected by the local backend.
          </p>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
          <p className="text-sm text-slate-500 dark:text-slate-400">Live scan count</p>
          <p className="mt-1 text-3xl font-semibold text-slate-950 dark:text-white">
            {liveScanCount}
          </p>
        </div>
      </section>

      <Panel>
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400">
            <motion.span
              animate={{ scale: [1, 1.18, 1], opacity: [0.75, 1, 0.75] }}
              transition={{ duration: 1.4, repeat: Infinity }}
              className="grid h-8 w-8 place-items-center rounded-lg bg-teal-500/15 text-teal-600 dark:text-teal-300"
            >
              <Radio size={17} />
            </motion.span>
            Browser link monitoring is ready
          </div>
          <div className="inline-flex items-center gap-2 rounded-full border border-slate-200 px-3 py-2 text-xs font-medium text-slate-500 dark:border-slate-800 dark:text-slate-400">
            <ShieldCheck size={15} className="text-teal-500" />
            {liveFeed.length}/50 items
          </div>
        </div>

        {liveFeed.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-300 p-6 text-center text-sm text-slate-500 dark:border-slate-800 dark:text-slate-400">
            Waiting for the first browser, email, or manual scan...
          </div>
        ) : (
          <div className="space-y-3">
            {liveFeed.map((event, index) => {
              const Icon = activityIcons[event.activityType] ?? Activity

              return (
                <motion.article
                  key={event.id}
                  initial={{ opacity: 0, x: -12 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: Math.min(index * 0.025, 0.2) }}
                  className={`rounded-lg border p-4 ${
                    event.status === 'Blocked'
                      ? 'border-rose-500/40 bg-rose-500/5'
                      : 'border-slate-200 dark:border-slate-800'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex min-w-0 gap-3">
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
                    </div>
                    <RiskBadge risk={event.status} />
                  </div>
                </motion.article>
              )
            })}
          </div>
        )}
      </Panel>

      <Panel>
        <div className="mb-4 flex items-center justify-between gap-3">
          <h2 className="text-lg font-semibold">System logs</h2>
          <span className="text-xs text-slate-500 dark:text-slate-400">
            Latest backend events
          </span>
        </div>
        {systemLogs.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Waiting for backend scan logs...
          </p>
        ) : (
          <div className="space-y-2">
            {systemLogs.slice(0, 6).map((log) => (
              <div
                key={log.id}
                className="rounded-lg border border-slate-200 p-3 text-sm dark:border-slate-800"
              >
                <div className="flex items-center justify-between gap-3">
                  <p className="font-medium">{log.event}</p>
                  <span className="text-xs text-slate-400">{formatTime(log.timestamp)}</span>
                </div>
                <p className="mt-1 text-slate-500 dark:text-slate-400">{log.message}</p>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  )
}
