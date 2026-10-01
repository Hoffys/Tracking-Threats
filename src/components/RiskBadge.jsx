import { riskStyles } from '../utils/detection'
import { hasContentWarnings, riskLabel } from '../utils/scanPresentation'

export function RiskBadge({ risk, categories = [] }) {
  const contentCaution = risk === 'Safe' && hasContentWarnings(categories)
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ring-1 ${contentCaution ? 'bg-amber-100 text-amber-800 ring-amber-300 dark:bg-amber-950/50 dark:text-amber-200 dark:ring-amber-700' : riskStyles[risk]}`}
    >
      {riskLabel(risk, categories)}
    </span>
  )
}
