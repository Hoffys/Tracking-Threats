import { AlertTriangle, CheckCircle2, ShieldCheck, SlidersHorizontal } from 'lucide-react'

import { categoryLabels, coverageLabel, hasIncompleteChecks, normalizeCategories, responseLabel } from '../utils/scanPresentation'

const getScoreBand = (score = 100) => {
  if (score >= 80) return 'Low indicator range: 80-100'
  if (score > 50) return 'Caution range: 51-79'
  return 'Danger range: 0-50'
}

const getExplanation = (scan) => {
  const warnings = scan?.warningSigns ?? []
  const status = scan?.status
  const mainSignal = warnings[0] ?? 'No strong indicator reported'
  const intel = scan?.threatIntel ?? []
  const matchedIntel = intel.filter((provider) => provider?.found).length
  const unavailableIntel = intel.filter((provider) => provider?.error || provider?.checked === false || provider?.skipped).length

  if (status === 'Dangerous' || scan?.blocked || scan?.responseStatus === 'Blocked') {
    return {
      title: 'Why risk was detected',
      icon: AlertTriangle,
      tone: 'text-rose-600 bg-rose-50 dark:bg-rose-950/40 dark:text-rose-300',
      summary:
        'Avoid opening links, downloading files, or sharing information from this source. The scan found risk indicators; this result alone does not prove that access was blocked.',
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
        'Verify the sender and destination before continuing. Do not enter passwords or send money until you have checked through an official channel.',
      mainSignal,
      matchedIntel,
      unavailableIntel,
    }
  }

  return {
    title: 'Appears safe based on this scan',
    icon: CheckCircle2,
    tone: 'text-emerald-700 bg-emerald-50 dark:bg-emerald-950/40 dark:text-emerald-300',
    summary: 'No strong phishing indicators were found in the checks that ran. Continue with normal caution, and never share passwords or OTPs. This assessment is not a guarantee of safety.',
    mainSignal,
    matchedIntel,
    unavailableIntel,
  }
}

export function ScanExplanation({ scan, manual = false }) {
  if (!scan) return null

  const explanation = getExplanation(scan)
  const Icon = explanation.icon
  const warningCount = scan.warningSigns?.length ?? 0
  const providerCount = scan.coverage?.checkedProviders ?? scan.threatIntel?.filter((provider) => provider?.checked === true && !provider.error && !provider.skipped).length ?? 0
  const categories = normalizeCategories(scan.categories)
  const contentCategories = categories.filter((category) => category.endsWith('-content'))
  const riskCategories = categories.filter((category) => !category.endsWith('-content'))

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

      <p className="mt-3 text-sm text-slate-600 dark:text-slate-300">
        Rule-based score: {scan.score}/100. This is not a calibrated probability.
      </p>
      <p className={`mt-2 text-sm ${hasIncompleteChecks(scan.coverage) ? 'text-amber-700 dark:text-amber-300' : 'text-slate-600 dark:text-slate-300'}`}>
        {coverageLabel(scan.coverage)}
      </p>
      {scan.coverage?.limitations?.length > 0 && (
        <ul className="mt-2 list-disc pl-5 text-sm text-slate-600 dark:text-slate-300">
          {scan.coverage.limitations.map((item, index) => <li key={index}>{item}</li>)}
        </ul>
      )}
      {riskCategories.length > 0 && <p className="mt-3 text-sm">Risk categories: {riskCategories.map((category) => categoryLabels[category]).join(', ')}.</p>}
      {contentCategories.length > 0 && (
        <p className="mt-3 text-sm text-amber-700 dark:text-amber-300">
          Content warnings: {contentCategories.map((category) => categoryLabels[category]).join(', ')}.
          {' '}These content categories do not establish phishing.
        </p>
      )}
      {scan.categoryWarnings?.length > 0 && (
        <div className="mt-3 text-sm text-amber-700 dark:text-amber-300">
          <p>Content category warnings (separate from phishing evidence):</p>
          <ul className="mt-1 list-disc pl-5">
            {scan.categoryWarnings.map((warning, index) => <li key={index}>{warning}</li>)}
          </ul>
        </div>
      )}
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
            {warningCount} warning{warningCount === 1 ? '' : 's'}, {providerCount} checked provider
            {providerCount === 1 ? '' : 's'}
          </p>
        </div>
        <div>
          <p className="text-xs font-semibold uppercase text-slate-400">System response</p>
          <p className="mt-1 text-sm font-semibold text-slate-700 dark:text-slate-200">
            {responseLabel(scan, manual)}
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
