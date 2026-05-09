import { ShieldCheck } from 'lucide-react'

export function ThreatIntelSummary({ providers = [] }) {
  const checkedProviders = providers.filter(Boolean)

  if (checkedProviders.length === 0) return null

  return (
    <div className="mt-4">
      <div className="mb-2 flex items-center gap-2 text-sm font-semibold">
        <ShieldCheck size={17} className="text-sky-500" />
        Threat intelligence
      </div>
      <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-300">
        {checkedProviders.map((provider) => {
          const state = provider.error
            ? 'Lookup unavailable'
            : provider.found
              ? 'Matched'
              : 'No match'

          return (
            <li key={`${provider.provider}-${provider.ipAddress ?? provider.host ?? state}`}>
              <span className="font-medium">{provider.provider}:</span> {state}
              {provider.warning ? ` - ${provider.warning}` : ''}
            </li>
          )
        })}
      </ul>
    </div>
  )
}
