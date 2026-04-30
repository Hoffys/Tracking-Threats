import { useMemo, useState } from 'react'
import {
  Archive,
  CheckCheck,
  CircleX,
  Eye,
  FileClock,
  Info,
  ShieldCheck,
  ShieldX,
  Trash2,
  X,
} from 'lucide-react'
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

const reviewLabels = {
  active: 'Active',
  marked_safe: 'Marked safe',
  confirmed_threat: 'Confirmed threat',
  archived: 'Archived',
}

function DetailItem({ label, value }) {
  return (
    <div>
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">{label}</p>
      <p className="mt-1 break-words text-sm font-medium text-slate-700 dark:text-slate-200">
        {value}
      </p>
    </div>
  )
}

function ThreatReviewModal({ onAction, onClose, threat }) {
  if (!threat) return null

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/65 p-4">
      <div className="w-full max-w-2xl rounded-lg border border-slate-200 bg-white p-5 shadow-2xl dark:border-slate-800 dark:bg-slate-900">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-sm font-medium text-teal-700 dark:text-teal-300">
              Threat Review
            </p>
            <h2 className="mt-1 text-xl font-semibold">Flagged threat details</h2>
          </div>
          <button
            className="grid h-9 w-9 place-items-center rounded-lg border border-slate-200 text-slate-500 dark:border-slate-800"
            type="button"
            onClick={onClose}
            aria-label="Close review modal"
          >
            <X size={18} />
          </button>
        </div>

        <div className="mt-5 grid gap-4 rounded-lg bg-slate-100 p-4 dark:bg-slate-950 sm:grid-cols-2">
          <DetailItem label="Threat type" value={threat.type} />
          <DetailItem label="URL/email" value={threat.target} />
          <DetailItem label="Safety score" value={`${threat.score}/100`} />
          <DetailItem label="Timestamp" value={formatTime(threat.blockedAt)} />
        </div>

        <div className="mt-5 space-y-4">
          <div>
            <p className="text-sm font-semibold">Detection reason</p>
            <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">{threat.reason}</p>
          </div>

          <div>
            <p className="text-sm font-semibold">Warning signs</p>
            {threat.warningSigns?.length > 0 ? (
              <ul className="mt-2 space-y-1 text-sm text-slate-600 dark:text-slate-300">
                {threat.warningSigns.map((sign) => (
                  <li key={sign}>- {sign}</li>
                ))}
              </ul>
            ) : (
              <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
                No warning signs were saved with this threat.
              </p>
            )}
          </div>
        </div>

        <div className="mt-6 flex flex-wrap justify-end gap-2">
          <button
            className="inline-flex items-center gap-2 rounded-lg border border-emerald-500/40 px-3 py-2 text-sm font-medium text-emerald-700 dark:text-emerald-300"
            type="button"
            onClick={() => onAction(threat.id, 'marked_safe')}
          >
            <ShieldCheck size={16} />
            Mark as Safe
          </button>
          <button
            className="inline-flex items-center gap-2 rounded-lg border border-rose-500/40 px-3 py-2 text-sm font-medium text-rose-700 dark:text-rose-300"
            type="button"
            onClick={() => onAction(threat.id, 'confirmed_threat')}
          >
            <ShieldX size={16} />
            Confirm Threat
          </button>
          <button
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm font-medium dark:border-slate-800"
            type="button"
            onClick={() => onAction(threat.id, 'archived')}
          >
            <Archive size={16} />
            Archive
          </button>
        </div>
      </div>
    </div>
  )
}

export function Alerts() {
  const {
    acknowledgeAlert,
    alerts,
    clearAlerts,
    clearFlaggedThreats,
    clearReviewedThreats,
    flaggedThreats,
    reviewThreat,
    threatAuditLogs,
  } = useThreats()
  const [selectedThreat, setSelectedThreat] = useState(null)

  const reviewedInActiveView = useMemo(
    () => flaggedThreats.filter((threat) => threat.reviewStatus !== 'active').length,
    [flaggedThreats],
  )

  const handleThreatAction = async (id, status) => {
    await reviewThreat(id, status)
    setSelectedThreat(null)
  }

  const handleClearAlerts = async () => {
    if (!window.confirm('Clear all alert records from the alerts table?')) return
    await clearAlerts()
  }

  const handleClearFlaggedThreats = async () => {
    if (!window.confirm('Clear flagged threats from the active view? Records will stay in the database.')) {
      return
    }
    await clearFlaggedThreats()
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm font-medium text-teal-700 dark:text-teal-300">Alerts</p>
          <h1 className="text-2xl font-semibold">Threat review queue</h1>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            className="inline-flex items-center gap-2 rounded-lg border border-rose-500/30 px-3 py-2 text-sm font-medium text-rose-700 disabled:cursor-not-allowed disabled:opacity-50 dark:text-rose-300"
            type="button"
            onClick={handleClearAlerts}
            disabled={alerts.length === 0}
          >
            <Trash2 size={16} />
            {alerts.length > 0 ? `Clear Alerts (${alerts.length})` : 'No Alerts'}
          </button>
          <button
            className="inline-flex items-center gap-2 rounded-lg border border-rose-500/30 px-3 py-2 text-sm font-medium text-rose-700 disabled:cursor-not-allowed disabled:opacity-50 dark:text-rose-300"
            type="button"
            onClick={handleClearFlaggedThreats}
            disabled={flaggedThreats.length === 0}
          >
            <Trash2 size={16} />
            {flaggedThreats.length > 0
              ? `Clear Flagged (${flaggedThreats.length})`
              : 'No Flagged Threats'}
          </button>
          <button
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm font-medium text-slate-700 disabled:cursor-not-allowed disabled:opacity-50 dark:border-slate-800 dark:text-slate-200"
            type="button"
            onClick={clearReviewedThreats}
            disabled={reviewedInActiveView === 0}
          >
            <Trash2 size={16} />
            {reviewedInActiveView > 0
              ? `Clear Reviewed Logs (${reviewedInActiveView})`
              : 'No Reviewed Logs'}
          </button>
        </div>
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
                {reviewedInActiveView > 0
                  ? ` ${reviewedInActiveView} reviewed item${
                      reviewedInActiveView === 1 ? '' : 's'
                    } can be cleared from this active view.`
                  : ''}
              </p>
            </div>
          </div>
        </div>
      )}

      <Panel>
        <div className="mb-4 flex items-center gap-2">
          <ShieldX size={18} className="text-rose-500" />
          <h2 className="text-lg font-semibold">Flagged threats</h2>
        </div>
        {flaggedThreats.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">
            No flagged threats are active. Dangerous scans will appear here for review.
          </p>
        ) : (
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
                    {threat.reviewStatus !== 'active' && (
                      <p className="mt-1 text-xs font-semibold uppercase tracking-wide text-teal-700 dark:text-teal-300">
                        {reviewLabels[threat.reviewStatus] ?? threat.reviewStatus}
                      </p>
                    )}
                  </div>
                  <RiskBadge risk="Dangerous" />
                </div>
                <p className="mt-3 text-sm text-slate-600 dark:text-slate-300">
                  {threat.reason}
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                  <button
                    className="inline-flex items-center gap-2 rounded-lg bg-teal-600 px-3 py-2 text-sm font-semibold text-white"
                    type="button"
                    onClick={() => setSelectedThreat(threat)}
                  >
                    <Eye size={16} />
                    Review
                  </button>
                  <button
                    className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm font-medium dark:border-slate-800"
                    type="button"
                    onClick={() => handleThreatAction(threat.id, 'archived')}
                  >
                    <Archive size={16} />
                    Archive
                  </button>
                  <button
                    className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm font-medium dark:border-slate-800"
                    type="button"
                    onClick={() => setSelectedThreat(threat)}
                  >
                    <Info size={16} />
                    Details
                  </button>
                </div>
              </article>
            ))}
          </div>
        )}
      </Panel>

      <Panel>
        <div className="mb-4 flex items-center gap-2">
          <FileClock size={18} className="text-teal-500" />
          <h2 className="text-lg font-semibold">Audit Logs / History</h2>
        </div>
        {threatAuditLogs.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Reviewed and archived threats will be retained here.
          </p>
        ) : (
          <div className="space-y-3">
            {threatAuditLogs.map((threat) => (
              <article
                key={threat.id}
                className="rounded-lg border border-slate-200 p-4 dark:border-slate-800"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate font-medium">{threat.target}</p>
                    <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                      {reviewLabels[threat.reviewStatus] ?? threat.reviewStatus} •{' '}
                      {formatTime(threat.reviewedAt ?? threat.blockedAt)} • Safety score{' '}
                      {threat.score}/100
                    </p>
                  </div>
                  <RiskBadge risk={threat.reviewStatus === 'marked_safe' ? 'Safe' : 'Dangerous'} />
                </div>
                <p className="mt-3 text-sm text-slate-600 dark:text-slate-300">
                  {threat.reason}
                </p>
              </article>
            ))}
          </div>
        )}
      </Panel>

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
                  <DetailItem label="Threat type" value={alert.threatType ?? 'Unknown'} />
                  <DetailItem label="Risk level" value={alert.riskLevel ?? alert.severity} />
                  <DetailItem
                    label="Recommended action"
                    value={alert.recommendedAction ?? 'Review and verify before taking action.'}
                  />
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

      <ThreatReviewModal
        threat={selectedThreat}
        onClose={() => setSelectedThreat(null)}
        onAction={handleThreatAction}
      />
    </div>
  )
}
