import { riskStyles } from '../utils/detection'
import { hasPiracyContent, riskLabel } from '../utils/scanPresentation'

export function RiskBadge({ risk, categories = [] }) {
  const piracyCaution = risk === 'Safe' && hasPiracyContent(categories)
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ring-1 ${piracyCaution ? 'bg-amber-100 text-amber-800 ring-amber-300 dark:bg-amber-950/50 dark:text-amber-200 dark:ring-amber-700' : riskStyles[risk]}`}
    >
      {riskLabel(risk, categories)}
    </span>
  )
}
