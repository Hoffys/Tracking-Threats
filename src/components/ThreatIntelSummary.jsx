import { ShieldCheck } from 'lucide-react'
import { summarizeThreatIntelProviders } from '../utils/scanPresentation'

export function ThreatIntelSummary({ providers = [] }) {
  const providerSummaries = summarizeThreatIntelProviders(providers)

  if (providerSummaries.length === 0) return null

  return (
    <div className="mt-4">
      <div className="mb-2 flex items-center gap-2 text-sm font-semibold">
        <ShieldCheck size={17} className="text-sky-500" />
        Threat intelligence
      </div>
      <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-300">
        {providerSummaries.map((provider) => (
          <li key={provider.provider}>
            <span className="font-medium">{provider.provider}:</span> {provider.summary}
          </li>
        ))}
      </ul>
    </div>
  )
}
