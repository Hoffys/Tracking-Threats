import { riskStyles } from '../utils/detection'
import { hasIncompleteChecks, riskLabel } from '../utils/scanPresentation'

export function RiskBadge({ risk, coverage }) {
  const tone = risk === 'Safe' && hasIncompleteChecks(coverage) ? 'Suspicious' : risk
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ring-1 ${riskStyles[tone]}`}
    >
      {riskLabel(risk, coverage)}
    </span>
  )
}
