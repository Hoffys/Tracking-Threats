import { CheckCheck, CircleX, ShieldX } from 'lucide-react'
import { Panel } from '../components/Panel'
import { RiskBadge } from '../components/RiskBadge'
import { useThreats } from '../hooks/useThreats'

const formatTime = (date) =>
  new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(new Date(date))

export function Alerts() {
  const { acknowledgeAlert, alerts, flaggedThreats } = useThreats()

  return (
    <div className="space-y-5">
      <div>
        <p className="text-sm font-medium text-teal-700 dark:text-teal-300">Alerts</p>
        <h1 className="text-2xl font-semibold">Threat review queue</h1>
      </div>

      {flaggedThreats.length > 0 && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-600 p-4 text-white shadow-sm">
          <div className="flex items-start gap-3">
            <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-white/15">
              <ShieldX size={21} />
            </span>
            <div>
              <p className="font-semibold">Threat Blocked Automatically</p>
              <p className="mt-1 text-sm text-rose-50">
                {flaggedThreats.length} dangerous scan
                {flaggedThreats.length === 1 ? '' : 's'} saved as flagged content.
              </p>
            </div>
          </div>
        </div>
      )}

      {flaggedThreats.length > 0 && (
        <Panel>
          <div className="mb-4 flex items-center gap-2">
            <ShieldX size={18} className="text-rose-500" />
            <h2 className="text-lg font-semibold">Flagged threats</h2>
          </div>
          <div className="space-y-3">
            {flaggedThreats.map((threat) => (
              <article
                key={threat.id}
                className="rounded-lg border border-rose-500/25 bg-rose-500/5 p-4"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate font-medium">{threat.target}</p>
                    <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                      {threat.type} • Blocked {formatTime(threat.blockedAt)} • Safety score{' '}
                      {threat.score}/100
                    </p>
                  </div>
                  <RiskBadge risk="Dangerous" />
                </div>
                <p className="mt-3 text-sm text-slate-600 dark:text-slate-300">
                  {threat.reason}
                </p>
              </article>
            ))}
          </div>
        </Panel>
      )}

      <Panel>
        {alerts.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">
            No alerts are waiting. Medium, high, and critical scans will appear here.
          </p>
        ) : (
          <div className="space-y-3">
            {alerts.map((alert) => (
              <article
                key={alert.id}
                className="rounded-lg border border-slate-200 p-4 dark:border-slate-800"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate font-medium">{alert.title}</p>
                    <p className="mt-1 truncate text-sm text-slate-500 dark:text-slate-400">
                      {alert.source} • {formatTime(alert.time)}
                    </p>
                  </div>
                  <RiskBadge risk={alert.severity} />
                </div>
                <p className="mt-3 text-sm text-slate-600 dark:text-slate-300">
                  {alert.message}
                </p>
                <div className="mt-4 grid gap-3 rounded-lg bg-slate-100 p-3 text-sm dark:bg-slate-950 sm:grid-cols-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">
                      Threat type
                    </p>
                    <p className="mt-1 font-medium">{alert.threatType ?? 'Unknown'}</p>
                  </div>
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">
                      Risk level
                    </p>
                    <p className="mt-1 font-medium">{alert.riskLevel ?? alert.severity}</p>
                  </div>
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">
                      Recommended action
                    </p>
                    <p className="mt-1 font-medium">
                      {alert.recommendedAction ?? 'Review and verify before taking action.'}
                    </p>
                  </div>
                </div>
                <div className="mt-4 flex items-center justify-between gap-3">
                  <span className="text-xs uppercase tracking-wide text-slate-400">
                    {alert.status}
                  </span>
                  {alert.status === 'new' && (
                    <div className="flex flex-wrap gap-2">
                      <button
                        className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm font-medium dark:border-slate-800"
                        type="button"
                        onClick={() => acknowledgeAlert(alert.id)}
                      >
                        <CheckCheck size={16} />
                        Acknowledge
                      </button>
                      <button
                        className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm font-medium dark:border-slate-800"
                        type="button"
                        onClick={() => acknowledgeAlert(alert.id)}
                      >
                        <CircleX size={16} />
                        Dismiss
                      </button>
                    </div>
                  )}
                </div>
              </article>
            ))}
          </div>
        )}
      </Panel>
    </div>
  )
}
