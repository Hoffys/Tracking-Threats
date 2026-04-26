import { AlertTriangle, CheckCircle2, ScanSearch, ShieldAlert } from 'lucide-react'
import { useThreats } from '../hooks/useThreats'
import { Panel } from '../components/Panel'
import { RiskBadge } from '../components/RiskBadge'
import { StatCard } from '../components/StatCard'

export function Dashboard({ onNavigate }) {
  const { alerts, scanHistory, stats } = useThreats()
  const recent = scanHistory.slice(0, 4)

  return (
    <div className="space-y-5">
      <section className="grid gap-4 md:grid-cols-[1.5fr_1fr]">
        <div className="rounded-lg bg-slate-950 p-5 text-white dark:bg-slate-900">
          <p className="text-sm font-medium text-teal-300">Detection overview</p>
          <h1 className="mt-3 max-w-2xl text-3xl font-semibold leading-tight sm:text-4xl">
            Monitor suspicious mail, URLs, and scan activity from one local console.
          </h1>
          <div className="mt-5 flex flex-wrap gap-2">
            <button
              className="rounded-lg bg-teal-500 px-4 py-2 text-sm font-semibold text-slate-950"
              type="button"
              onClick={() => onNavigate('email')}
            >
              Analyze Email
            </button>
            <button
              className="rounded-lg border border-white/20 px-4 py-2 text-sm font-semibold text-white"
              type="button"
              onClick={() => onNavigate('manual')}
            >
              Manual Scan
            </button>
          </div>
        </div>
        <Panel className="flex flex-col justify-between">
          <div>
            <p className="text-sm text-slate-500 dark:text-slate-400">Current posture</p>
            <p className="mt-2 text-3xl font-semibold text-slate-950 dark:text-white">
              {stats.unreadAlerts > 0 ? 'Needs review' : 'Stable'}
            </p>
          </div>
          <div className="mt-6 space-y-3">
            {alerts.slice(0, 2).map((alert) => (
              <div key={alert.id} className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{alert.title}</p>
                  <p className="truncate text-xs text-slate-500 dark:text-slate-400">
                    {alert.source}
                  </p>
                </div>
                <RiskBadge risk={alert.severity} />
              </div>
            ))}
          </div>
        </Panel>
      </section>

      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard icon={ScanSearch} label="Total scans" value={stats.total} tone="teal" />
        <StatCard icon={ShieldAlert} label="Blocked threats" value={stats.blocked} tone="rose" />
        <StatCard icon={CheckCircle2} label="Clean results" value={stats.clean} tone="slate" />
        <StatCard icon={AlertTriangle} label="New alerts" value={stats.unreadAlerts} tone="amber" />
      </section>

      <Panel>
        <div className="mb-4 flex items-center justify-between gap-3">
          <h2 className="text-lg font-semibold">Recent scans</h2>
          <button
            className="text-sm font-medium text-teal-700 dark:text-teal-300"
            type="button"
            onClick={() => onNavigate('history')}
          >
            View all
          </button>
        </div>
        <div className="space-y-3">
          {recent.map((scan) => (
            <div
              key={scan.id}
              className="flex items-center justify-between gap-3 rounded-lg border border-slate-200 p-3 dark:border-slate-800"
            >
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">{scan.target}</p>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {scan.type} scan • Safety score {scan.score}/100
                </p>
              </div>
              <RiskBadge risk={scan.status ?? scan.risk} />
            </div>
          ))}
        </div>
      </Panel>
    </div>
  )
}
