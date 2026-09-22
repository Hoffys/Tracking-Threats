import {
  Database,
  ExternalLink,
  FileWarning,
  LockKeyhole,
  MailCheck,
  ShieldCheck,
  Trash2,
} from 'lucide-react'

const sections = [
  {
    icon: Database,
    title: 'Data processed',
    body: 'The service processes the submitted URL, sender details, message text, or a limited file-text preview to perform the requested scan. It records a random client and scan ID, redacted target metadata, SHA-256 where available, verdict, score, evidence, timestamps, and methodology version.',
  },
  {
    icon: LockKeyhole,
    title: 'Storage and access',
    body: 'Production is configured with STORE_SCAN_CONTENT=false, so raw email bodies, messages, and extracted file text are not retained after analysis. Results are stored in a private server-side scan repository. Each browser has a separate access credential; administrators can view redacted outcomes and operational logs, not raw submitted content.',
  },
  {
    icon: ExternalLink,
    title: 'External providers',
    body: 'Depending on configuration, URLs, domains, IP addresses, or file hashes may be sent to VirusTotal, Google Safe Browsing, URLhaus, PhishTank, AbuseIPDB, and DNS services. Railway hosts the application and stored results. Processing may occur outside the Philippines.',
  },
  {
    icon: Trash2,
    title: 'Retention and deletion',
    body: 'Scan records expire after 30 days by default. Security audit logs expire after 90 days. Clear History removes the current client scan records. Delete My Data also removes saved report-email settings and revokes the browser credential. Administrators may process verified deletion requests, with the action logged.',
  },
  {
    icon: MailCheck,
    title: 'Browser email consent',
    body: 'The browser extension keeps webmail scanning off until the user accepts the confidentiality notice. When enabled, it may process the visible sender, subject, message text, links, and visible Gmail inbox previews. Consent can be withdrawn at any time from the webmail monitor.',
  },
]

export function PrivacyNotice({ embedded = false, onNavigate }) {
  return (
    <div className="space-y-6">
      {!embedded && (
        <header className="border-b border-slate-200 pb-5 dark:border-slate-800">
          <p className="text-sm font-medium text-teal-700 dark:text-teal-300">Privacy Notice 2026.09</p>
          <h1 className="mt-1 text-2xl font-semibold">How scan data is handled</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600 dark:text-slate-300">
            Tracking Threats processes submitted data to identify phishing and malware indicators,
            explain the result, maintain security records, and deliver reports selected by the user.
          </p>
        </header>
      )}

      {embedded && (
        <div>
          <p className="text-sm font-medium text-teal-700 dark:text-teal-300">Privacy Notice 2026.09</p>
          <h2 className="mt-1 text-xl font-semibold">How scan data is handled</h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600 dark:text-slate-300">
            Tracking Threats processes submitted data to identify phishing and malware indicators,
            explain the result, maintain security records, and deliver reports selected by the user.
          </p>
        </div>
      )}

      <section className="divide-y divide-slate-200 border-y border-slate-200 dark:divide-slate-800 dark:border-slate-800">
        {sections.map(({ icon: Icon, title, body }) => (
          <article key={title} className="grid gap-3 py-5 md:grid-cols-[48px_220px_1fr]">
            <span className="grid h-10 w-10 place-items-center rounded-lg bg-teal-50 text-teal-700 dark:bg-teal-950/50 dark:text-teal-300"><Icon size={19} /></span>
            <h2 className="font-semibold">{title}</h2>
            <p className="text-sm leading-6 text-slate-600 dark:text-slate-300">{body}</p>
          </article>
        ))}
      </section>

      <section className="grid gap-5 lg:grid-cols-2">
        <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-800">
          <ShieldCheck size={20} className="text-teal-500" />
          <h2 className="mt-3 font-semibold">Your choices and rights</h2>
          <p className="mt-2 text-sm leading-6 text-slate-600 dark:text-slate-300">
            Do not submit an item you are not authorized to process. You may clear scan history,
            remove notification recipients, request correction, object to processing, or delete
            the client data available through this browser session.
          </p>
          <button type="button" onClick={() => onNavigate?.('settings')} className="mt-4 rounded-lg bg-teal-600 px-4 py-2.5 text-sm font-semibold text-white">Open data controls</button>
        </div>
        <div className="rounded-lg border border-amber-400/50 bg-amber-50 p-4 dark:bg-amber-950/20">
          <FileWarning size={20} className="text-amber-600" />
          <h2 className="mt-3 font-semibold">Important disclaimer</h2>
          <p className="mt-2 text-sm leading-6 text-slate-700 dark:text-slate-300">
            Results are automated risk assessments, not legal, forensic, or authenticity
            certifications. A Safe result only means no configured threat indicator was detected.
            Verify important requests and documents through the official sender or issuer.
          </p>
        </div>
      </section>

      <p className="border-t border-slate-200 pt-4 text-xs leading-5 text-slate-500 dark:border-slate-800 dark:text-slate-400">
        Privacy contact: Tracking Threats project team through the contact names shown in Settings.
        Data-subject concerns may also be raised with the institution supervising this capstone.
      </p>
    </div>
  )
}
