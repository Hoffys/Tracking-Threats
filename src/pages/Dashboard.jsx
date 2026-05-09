import {
  AlertTriangle,
  BellRing,
  CheckCircle2,
  ClipboardList,
  MailCheck,
  MonitorDot,
  ScanSearch,
  ShieldAlert,
} from 'lucide-react'
import { useThreats } from '../hooks/useThreats'
import { Panel } from '../components/Panel'
import { RiskBadge } from '../components/RiskBadge'
import { StatCard } from '../components/StatCard'

export function Dashboard({ onNavigate }) {
  const { alerts, scanHistory, stats } = useThreats()
  const tutorialSteps = [
    {
      title: 'Check the dashboard',
      description: 'Start by reviewing total scans, blocked threats, clean results, and new alerts.',
      icon: ClipboardList,
      action: 'Dashboard',
      page: 'dashboard',
    },
    {
      title: 'Analyze suspicious emails',
      description: 'Enter the sender, subject, and message body to check for phishing risk.',
      icon: MailCheck,
      action: 'Analyze Email',
      page: 'email',
    },
    {
      title: 'Scan links or files manually',
      description: 'Use manual scan when you need to check a URL, message, or file name.',
      icon: ScanSearch,
      action: 'Manual Scan',
      page: 'manual',
    },
    {
      title: 'Review alerts and history',
      description: 'Review flagged threats, scan history, and live activity to decide the next action.',
      icon: BellRing,
      action: 'View Alerts',
      page: 'alerts',
    },
  ]
  const riskOrder = { Dangerous: 0, Suspicious: 1, Safe: 2 }
  const recent = [...scanHistory]
    .sort((left, right) => {
      const leftRank = riskOrder[left.status] ?? 3
      const rightRank = riskOrder[right.status] ?? 3
      if (leftRank !== rightRank) return leftRank - rightRank
      return new Date(right.date).getTime() - new Date(left.date).getTime()
    })
    .slice(0, 4)

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
        <Panel className="overflow-hidden">
          <div>
            <p className="text-sm text-slate-500 dark:text-slate-400">Current posture</p>
            <p className="mt-2 text-3xl font-semibold text-slate-950 dark:text-white">
              {stats.unreadAlerts > 0 ? 'Needs review' : 'Stable'}
            </p>
          </div>
          <div className="mt-4 space-y-3">
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
        <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-sm font-medium text-teal-700 dark:text-teal-300">
              First-time user guide
            </p>
            <h2 className="mt-1 text-lg font-semibold text-slate-950 dark:text-white">
              How to use Tracking Threats
            </h2>
          </div>
          <button
            className="inline-flex w-fit items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-slate-700 transition hover:border-teal-300 hover:text-teal-700 dark:border-slate-800 dark:text-slate-200 dark:hover:border-teal-500 dark:hover:text-teal-300"
            type="button"
            onClick={() => onNavigate('monitor')}
          >
            <MonitorDot size={16} />
            Live Monitor
          </button>
        </div>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {tutorialSteps.map((step, index) => {
            const Icon = step.icon
            return (
              <div
                key={step.title}
                className="flex min-h-44 flex-col rounded-lg border border-slate-200 p-3 dark:border-slate-800"
              >
                <div className="flex items-start gap-3">
                  <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-teal-50 text-teal-700 dark:bg-teal-950/60 dark:text-teal-300">
                    <Icon size={18} />
                  </span>
                  <div className="min-w-0">
                    <p className="text-xs font-semibold uppercase text-slate-400">
                      Step {index + 1}
                    </p>
                    <h3 className="mt-1 text-sm font-semibold text-slate-950 dark:text-white">
                      {step.title}
                    </h3>
                  </div>
                </div>
                <p className="mt-3 flex-1 text-sm leading-6 text-slate-600 dark:text-slate-300">
                  {step.description}
                </p>
                <button
                  className="mt-3 inline-flex items-center justify-center rounded-lg bg-slate-100 px-3 py-2 text-sm font-semibold text-slate-800 transition hover:bg-teal-100 hover:text-teal-800 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-teal-950 dark:hover:text-teal-200"
                  type="button"
                  onClick={() => onNavigate(step.page)}
                >
                  {step.action}
                </button>
              </div>
            )
          })}
        </div>
      </Panel>

      <Panel>
        <div className="mb-4 flex items-center justify-between gap-3">
          <h2 className="text-lg font-semibold">Recent risk activity</h2>
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
                <p className="mt-1 text-xs font-medium text-slate-400">
                  Source: {scan.source}
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
