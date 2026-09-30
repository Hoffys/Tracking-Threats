import { riskStyles } from '../utils/detection'
import { riskLabel } from '../utils/scanPresentation'

export function RiskBadge({ risk }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ring-1 ${riskStyles[risk]}`}
    >
      {riskLabel(risk)}
    </span>
  )
}
