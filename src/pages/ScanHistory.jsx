import { Trash2 } from 'lucide-react'
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

export function ScanHistory() {
  const { clearHistory, scanHistory } = useThreats()

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-medium text-teal-700 dark:text-teal-300">Scan History</p>
          <h1 className="text-2xl font-semibold">Database scan records</h1>
        </div>
        <button
          className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm font-medium text-slate-700 dark:border-slate-800 dark:text-slate-200"
          type="button"
          onClick={clearHistory}
        >
          <Trash2 size={16} />
          Clear
        </button>
      </div>

      <Panel>
        {scanHistory.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">
            No scans yet. New email and manual scans will be saved in SQLite.
          </p>
        ) : (
          <div className="space-y-3">
            {scanHistory.map((scan) => (
              <article
                key={scan.id}
                className="rounded-lg border border-slate-200 p-4 dark:border-slate-800"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate font-medium">{scan.target}</p>
                    <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                      {scan.type} • {formatTime(scan.date)} • Safety score {scan.score}/100
                    </p>
                    {scan.responseStatus && (
                      <p className="mt-1 text-sm font-semibold text-rose-600 dark:text-rose-300">
                        Response: {scan.responseStatus}
                      </p>
                    )}
                  </div>
                  <RiskBadge risk={scan.status ?? scan.risk} />
                </div>
                <p className="mt-3 text-sm text-slate-600 dark:text-slate-300">
                  {scan.summary}
                </p>
                {scan.warningSigns?.length > 0 && (
                  <div className="mt-3">
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">
                      Warning signs
                    </p>
                    <ul className="mt-2 space-y-1 text-sm text-slate-600 dark:text-slate-300">
                      {scan.warningSigns.map((sign) => (
                        <li key={sign}>- {sign}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {(scan.recommendations?.length > 0 || scan.recommendation) && (
                  <div className="mt-3">
                    <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">
                      Recommendations
                    </p>
                    <ul className="mt-2 space-y-1 text-sm text-slate-600 dark:text-slate-300">
                      {(scan.recommendations ?? [scan.recommendation]).map((recommendation) => (
                        <li key={recommendation}>- {recommendation}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </article>
            ))}
          </div>
        )}
      </Panel>
    </div>
  )
}
