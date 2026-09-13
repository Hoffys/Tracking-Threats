import { AlertTriangle, CheckCircle2, ShieldCheck, SlidersHorizontal } from 'lucide-react'

const getStatusLabel = (scan) => {
  if (scan?.responseStatus === 'Blocked' || scan?.blocked) return 'Blocked'
  if (scan?.status === 'Dangerous') return 'Blocked'
  if (scan?.status === 'Suspicious') return 'Review'
  return 'Allowed'
}

const getScoreBand = (score = 100) => {
  if (score >= 80) return 'Safe range: 80-100'
  if (score > 50) return 'Caution range: 51-79'
  return 'Danger range: 0-50'
}

const getExplanation = (scan) => {
  const warnings = scan?.warningSigns ?? []
  const status = scan?.status
  const mainSignal = warnings[0] ?? 'No strong phishing indicator'
  const intel = scan?.threatIntel ?? []
  const matchedIntel = intel.filter((provider) => provider?.found).length
  const unavailableIntel = intel.filter((provider) => provider?.error).length

  if (status === 'Dangerous' || scan?.blocked || scan?.responseStatus === 'Blocked') {
    return {
      title: 'Why this was blocked',
      icon: AlertTriangle,
      tone: 'text-rose-600 bg-rose-50 dark:bg-rose-950/40 dark:text-rose-300',
      summary:
        'The safety score reached the danger range because one or more high-risk indicators were found.',
      mainSignal,
      matchedIntel,
      unavailableIntel,
    }
  }

  if (status === 'Suspicious') {
    return {
      title: 'Why this needs caution',
      icon: SlidersHorizontal,
      tone: 'text-amber-600 bg-amber-50 dark:bg-amber-950/40 dark:text-amber-300',
      summary:
        'The scan found warning signs, but the score did not reach the automatic block threshold.',
      mainSignal,
      matchedIntel,
      unavailableIntel,
    }
  }

  return {
    title: 'Why this was marked safe',
    icon: CheckCircle2,
    tone: 'text-emerald-700 bg-emerald-50 dark:bg-emerald-950/40 dark:text-emerald-300',
    summary:
      'The scan did not find strong phishing indicators in the checked rules and reputation signals.',
    mainSignal,
    matchedIntel,
    unavailableIntel,
  }
}

export function ScanExplanation({ scan }) {
  if (!scan) return null

  const explanation = getExplanation(scan)
  const Icon = explanation.icon
  const warningCount = scan.warningSigns?.length ?? 0
  const providerCount = scan.threatIntel?.length ?? 0

  return (
    <div className="mt-4 rounded-lg bg-slate-50 p-4 dark:bg-slate-950/60">
      <div className="flex items-start gap-3">
        <span className={`grid h-10 w-10 shrink-0 place-items-center rounded-lg ${explanation.tone}`}>
          <Icon size={20} />
        </span>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-slate-950 dark:text-white">
            {explanation.title}
          </h3>
          <p className="mt-1 text-sm leading-6 text-slate-600 dark:text-slate-300">
            {explanation.summary}
          </p>
        </div>
      </div>

      <div className="mt-4 grid gap-3 md:grid-cols-4">
        <div>
          <p className="text-xs font-semibold uppercase text-slate-400">Score band</p>
          <p className="mt-1 text-sm font-semibold text-slate-700 dark:text-slate-200">
            {getScoreBand(scan.score)}
          </p>
        </div>
        <div>
          <p className="text-xs font-semibold uppercase text-slate-400">Main signal</p>
          <p className="mt-1 text-sm font-semibold text-slate-700 dark:text-slate-200">
            {explanation.mainSignal}
          </p>
        </div>
        <div>
          <p className="text-xs font-semibold uppercase text-slate-400">Signals found</p>
          <p className="mt-1 text-sm font-semibold text-slate-700 dark:text-slate-200">
            {warningCount} warning{warningCount === 1 ? '' : 's'}, {providerCount} provider
            {providerCount === 1 ? '' : 's'}
          </p>
        </div>
        <div>
          <p className="text-xs font-semibold uppercase text-slate-400">System response</p>
          <p className="mt-1 text-sm font-semibold text-slate-700 dark:text-slate-200">
            {getStatusLabel(scan)}
          </p>
        </div>
      </div>

      {(explanation.matchedIntel > 0 || explanation.unavailableIntel > 0) && (
        <div className="mt-4 flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
          <ShieldCheck size={16} className="shrink-0 text-sky-500" />
          <span>
            Threat intel: {explanation.matchedIntel} matched, {explanation.unavailableIntel}{' '}
            unavailable.
          </span>
        </div>
      )}
    </div>
  )
}
