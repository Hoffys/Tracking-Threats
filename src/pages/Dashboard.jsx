import {
  AlertTriangle,
  BarChart3,
  BellRing,
  CheckCircle2,
  ClipboardList,
  MailCheck,
  MonitorDot,
  PieChart,
  ScanSearch,
  ShieldAlert,
  Target,
} from 'lucide-react'
import { useThreats } from '../hooks/useThreats'
import { Panel } from '../components/Panel'
import { RiskBadge } from '../components/RiskBadge'
import { StatCard } from '../components/StatCard'

const dayFormatter = new Intl.DateTimeFormat(undefined, { weekday: 'short' })

const getScanTime = (scan) => new Date(scan.date).getTime()

const countBy = (items, getKey) =>
  items.reduce((counts, item) => {
    const key = getKey(item)
    if (!key) return counts
    counts[key] = (counts[key] ?? 0) + 1
    return counts
  }, {})

const toSortedEntries = (counts, limit = 5) =>
  Object.entries(counts)
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, limit)

const getLastSevenDays = (scans) => {
  const today = new Date()
  today.setHours(0, 0, 0, 0)

  return Array.from({ length: 7 }, (_, index) => {
    const day = new Date(today)
    day.setDate(today.getDate() - (6 - index))
    const nextDay = new Date(day)
    nextDay.setDate(day.getDate() + 1)
    const dayScans = scans.filter((scan) => {
      const time = getScanTime(scan)
      return time >= day.getTime() && time < nextDay.getTime()
    })

    return {
      label: dayFormatter.format(day),
      total: dayScans.length,
      blocked: dayScans.filter((scan) => scan.status === 'Dangerous' || scan.blocked).length,
    }
  })
}

export function Dashboard({ onNavigate }) {
  const { alerts, flaggedThreats, scanHistory, stats, threatAuditLogs } = useThreats()
  const tutorialSteps = [
    {
      title: 'Check the dashboard',
      description: 'Start by reviewing total scans, blocked threats, clean results, and new alerts.',
      icon: ClipboardList,
      action: 'Dashboard',
      page: 'dashboard',
    },
    {
      title: 'Manual email check',
      description: 'Paste a sender, subject, and email body when automatic webmail scanning is not available.',
      icon: MailCheck,
      action: 'Open Scan',
      page: 'manual',
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
  const trend = getLastSevenDays(scanHistory)
  const maxTrendTotal = Math.max(1, ...trend.map((day) => day.total))
  const typeBreakdown = toSortedEntries(countBy(scanHistory, (scan) => scan.type), 4)
  const warningSigns = toSortedEntries(
    countBy(
      scanHistory.flatMap((scan) => scan.warningSigns ?? []),
      (sign) => sign,
    ),
    5,
  )
  const riskyTargets = [...scanHistory]
    .filter((scan) => scan.status === 'Dangerous' || scan.status === 'Suspicious' || scan.blocked)
    .sort((left, right) => {
      if (left.score !== right.score) return left.score - right.score
      return getScanTime(right) - getScanTime(left)
    })
    .slice(0, 5)
  const pendingReviews = flaggedThreats.filter((threat) => threat.reviewStatus === 'active')
  const reviewedThreats = threatAuditLogs.length
  const totalTypeBreakdown = Math.max(
    1,
    typeBreakdown.reduce((sum, [, count]) => sum + count, 0),
  )

  return (
    <div className="space-y-5">
      <section className="grid gap-4 md:grid-cols-[1.5fr_1fr]">
        <div className="rounded-lg border border-emerald-300 bg-emerald-100/80 p-5 text-emerald-950 shadow-[0_16px_36px_rgba(5,150,105,0.12)] dark:border-emerald-700 dark:bg-emerald-950/35 dark:text-white">
          <p className="text-sm font-medium text-emerald-700 dark:text-emerald-300">
            Automated threat detection
          </p>
          <div className="mt-4 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex min-w-0 items-center gap-4">
              <span className="grid h-16 w-16 shrink-0 place-items-center rounded-lg bg-emerald-500 text-white shadow-[0_14px_28px_rgba(5,150,105,0.25)]">
                <ShieldAlert size={30} />
              </span>
              <div className="min-w-0">
                <h1 className="text-2xl font-semibold leading-tight sm:text-3xl">
                  System Active & Monitoring
                </h1>
                <p className="mt-1 text-sm text-emerald-800 dark:text-emerald-200">
                  All protection modules operational
                </p>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-5 text-right">
              <div>
                <p className="text-xs font-medium text-emerald-700 dark:text-emerald-300">
                  Total Scans
                </p>
                <p className="text-3xl font-semibold">{stats.total}</p>
              </div>
              <div>
                <p className="text-xs font-medium text-emerald-700 dark:text-emerald-300">
                  Blocked
                </p>
                <p className="text-3xl font-semibold">{stats.blocked}</p>
              </div>
            </div>
          </div>
          <div className="mt-5 flex flex-wrap gap-2">
            <button
              className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-emerald-700"
              type="button"
              onClick={() => onNavigate('manual')}
            >
              Manual Scan
            </button>
            <button
              className="rounded-lg border border-emerald-300 bg-white/60 px-4 py-2 text-sm font-semibold text-emerald-800 transition hover:bg-white dark:border-emerald-700 dark:bg-slate-900/40 dark:text-emerald-200 dark:hover:bg-slate-900"
              type="button"
              onClick={() => onNavigate('monitor')}
            >
              Live Monitor
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

      <section className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
        <Panel>
          <div className="mb-4 flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium text-teal-700 dark:text-teal-300">
                Seven-day scan trend
              </p>
              <h2 className="mt-1 text-lg font-semibold text-slate-950 dark:text-white">
                Activity and blocked threats
              </h2>
            </div>
            <span className="grid h-10 w-10 place-items-center rounded-lg bg-teal-50 text-teal-700 dark:bg-teal-950/60 dark:text-teal-300">
              <BarChart3 size={20} />
            </span>
          </div>
          <div className="grid h-48 grid-cols-7 items-end gap-3">
            {trend.map((day) => (
              <div key={day.label} className="flex h-full flex-col justify-end gap-2">
                <div className="flex flex-1 items-end justify-center gap-1">
                  <span
                    className="w-3 rounded-t-md bg-teal-500 shadow-[0_0_12px_rgba(20,184,166,0.35)]"
                    style={{ height: `${Math.max(8, (day.total / maxTrendTotal) * 100)}%` }}
                    title={`${day.total} total scans`}
                  />
                  <span
                    className="w-3 rounded-t-md bg-rose-500 shadow-[0_0_12px_rgba(244,63,94,0.28)]"
                    style={{ height: `${Math.max(4, (day.blocked / maxTrendTotal) * 100)}%` }}
                    title={`${day.blocked} blocked threats`}
                  />
                </div>
                <div className="text-center">
                  <p className="text-xs font-semibold text-slate-700 dark:text-slate-200">
                    {day.total}
                  </p>
                  <p className="text-xs text-slate-400">{day.label}</p>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 flex flex-wrap gap-4 text-xs font-medium text-slate-500 dark:text-slate-400">
            <span className="inline-flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-teal-500" />
              Total scans
            </span>
            <span className="inline-flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-rose-500" />
              Blocked
            </span>
          </div>
        </Panel>

        <Panel>
          <div className="mb-4 flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium text-teal-700 dark:text-teal-300">
                Threat breakdown
              </p>
              <h2 className="mt-1 text-lg font-semibold text-slate-950 dark:text-white">
                Scan types
              </h2>
            </div>
            <span className="grid h-10 w-10 place-items-center rounded-lg bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200">
              <PieChart size={20} />
            </span>
          </div>
          <div className="space-y-3">
            {typeBreakdown.length > 0 ? (
              typeBreakdown.map(([type, count]) => (
                <div key={type}>
                  <div className="mb-1 flex items-center justify-between text-sm">
                    <span className="font-medium">{type}</span>
                    <span className="text-slate-500 dark:text-slate-400">{count}</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                    <div
                      className="h-full rounded-full bg-teal-500"
                      style={{ width: `${(count / totalTypeBreakdown) * 100}%` }}
                    />
                  </div>
                </div>
              ))
            ) : (
              <p className="text-sm text-slate-500 dark:text-slate-400">No scans yet.</p>
            )}
          </div>
        </Panel>
      </section>

      <section className="grid gap-4 lg:grid-cols-3">
        <Panel>
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 className="text-lg font-semibold">Common warning signs</h2>
            <AlertTriangle size={19} className="text-amber-500" />
          </div>
          <div className="space-y-3">
            {warningSigns.length > 0 ? (
              warningSigns.map(([sign, count]) => (
                <div
                  key={sign}
                  className="rounded-lg border border-slate-200 p-3 dark:border-slate-800"
                >
                  <p className="line-clamp-2 text-sm font-medium">{sign}</p>
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                    Seen {count} time{count === 1 ? '' : 's'}
                  </p>
                </div>
              ))
            ) : (
              <p className="text-sm text-slate-500 dark:text-slate-400">
                No warning signs recorded.
              </p>
            )}
          </div>
        </Panel>

        <Panel>
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 className="text-lg font-semibold">Top risky targets</h2>
            <Target size={19} className="text-rose-500" />
          </div>
          <div className="space-y-3">
            {riskyTargets.length > 0 ? (
              riskyTargets.map((scan) => (
                <div
                  key={scan.id}
                  className="flex items-center justify-between gap-3 rounded-lg border border-slate-200 p-3 dark:border-slate-800"
                >
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{scan.target}</p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      {scan.type} - Safety score {scan.score}/100
                    </p>
                  </div>
                  <RiskBadge risk={scan.status ?? scan.risk} />
                </div>
              ))
            ) : (
              <p className="text-sm text-slate-500 dark:text-slate-400">
                No risky targets recorded.
              </p>
            )}
          </div>
        </Panel>

        <Panel>
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 className="text-lg font-semibold">Review queue</h2>
            <ShieldAlert size={19} className="text-rose-500" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
              <p className="text-2xl font-semibold text-slate-950 dark:text-white">
                {pendingReviews.length}
              </p>
              <p className="text-sm text-slate-500 dark:text-slate-400">Pending</p>
            </div>
            <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
              <p className="text-2xl font-semibold text-slate-950 dark:text-white">
                {reviewedThreats}
              </p>
              <p className="text-sm text-slate-500 dark:text-slate-400">Reviewed</p>
            </div>
          </div>
          <button
            className="mt-4 inline-flex w-full items-center justify-center rounded-lg bg-slate-100 px-3 py-2 text-sm font-semibold text-slate-800 transition hover:bg-teal-100 hover:text-teal-800 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-teal-950 dark:hover:text-teal-200"
            type="button"
            onClick={() => onNavigate('alerts')}
          >
            Open Alerts
          </button>
        </Panel>
      </section>

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
