import { BookOpenCheck, Info, ScrollText } from 'lucide-react'
import { Methodology } from './Methodology'
import { PrivacyNotice } from './PrivacyNotice'

const tabs = [
  { id: 'methodology', label: 'Methodology', icon: BookOpenCheck },
  { id: 'privacy', label: 'Privacy Notice', icon: ScrollText },
]

export function About({ aboutSection = 'methodology', onNavigate }) {
  const activeSection = aboutSection === 'privacy' ? 'privacy' : 'methodology'

  return (
    <div className="space-y-6">
      <header className="border-b border-slate-200 pb-5 dark:border-slate-800">
        <div className="flex items-center gap-2 text-sm font-medium text-teal-700 dark:text-teal-300">
          <Info size={17} />
          About Tracking Threats
        </div>
        <h1 className="mt-2 text-2xl font-semibold">System methodology and privacy</h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600 dark:text-slate-300">
          Review how the scanner reaches a verdict and how submitted data is processed,
          retained, and deleted.
        </p>
      </header>

      <div
        className="flex gap-1 overflow-x-auto border-b border-slate-200 dark:border-slate-800"
        role="tablist"
        aria-label="About sections"
      >
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={activeSection === id}
            onClick={() => onNavigate?.(id)}
            className={`inline-flex shrink-0 items-center gap-2 border-b-2 px-4 py-3 text-sm font-semibold transition ${
              activeSection === id
                ? 'border-teal-500 text-teal-700 dark:text-teal-300'
                : 'border-transparent text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'
            }`}
          >
            <Icon size={17} />
            {label}
          </button>
        ))}
      </div>

      {activeSection === 'methodology' ? (
        <Methodology embedded />
      ) : (
        <PrivacyNotice embedded onNavigate={onNavigate} />
      )}
    </div>
  )
}
