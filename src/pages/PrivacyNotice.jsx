import {
  Database,
  ExternalLink,
  FileWarning,
  Globe2,
  HardDrive,
  LockKeyhole,
  MailCheck,
  SearchCheck,
  ShieldCheck,
  Trash2,
} from 'lucide-react'

const sections = [
  {
    icon: Globe2,
    title: 'Automatic website URL monitoring',
    body: 'The browser extension automatically checks eligible top-level website navigation URLs. A URL sent for checking can include its host, path, and query parameters. URL scans are sent to the Tracking Threats backend for analysis and may be saved in this browser client’s Scan History. The service may also request a submitted public URL to inspect the page and its redirects. This monitoring does not wait for a separate confirmation on each visit. URLs that are locally allowed or otherwise excluded from scanning may not be sent.',
  },
  {
    icon: SearchCheck,
    title: 'Search-result monitoring',
    body: 'Search-result monitoring stays off until you choose a mode in the browser search monitor. It supports Google, Bing, DuckDuckGo, Yahoo, Brave, Ecosia, Startpage, and Yandex. Saved monitoring sends eligible destination URLs from visible results to the backend and saves scan records in Scan History. Preview-only sends eligible URLs for analysis without creating Scan History records. Turning monitoring off stops future search-result scans; it does not delete existing records. This feature does not send search terms or unrelated search-page content, although a destination URL may itself contain query parameters. You can review or change this choice in Search Monitor privacy settings.',
  },
  {
    icon: MailCheck,
    title: 'Browser email consent',
    body: 'Email scanning is off until you accept the confidentiality notice. After consent, the extension can inspect opened messages on supported Gmail, Outlook, Yahoo Mail, Proton Mail, iCloud Mail, Zoho Mail, AOL Mail, and Mail.com pages. It sends the visible sender, subject, message text, and links to the backend for analysis. Gmail supports batch scanning of rendered previews in the currently selected mail view. Outlook Cloud supports an explicit Scan Folder action that opens conversations in the selected Inbox or Sent Items view and scans individually identified messages visible in the reading pane. Opening messages may change their read status according to your Outlook settings. Outlook conversations may contain collapsed or unloaded messages; those conversations are reported as incomplete when the extension cannot verify all messages. The extension does not navigate to other folders or automatically scroll the list. Batch sizes are 10, 20, 30, 40, or 50 messages. Messages may contain personal, health, financial, or authentication information. Do not scan messages unless you are authorized to submit them. Use the monitor’s Turn off control to withdraw consent and stop future email scans. Withdrawing consent does not delete scan records already saved.',
  },
  {
    icon: FileWarning,
    title: 'User-triggered page inspection',
    body: 'If you choose Inspect this page from the extension popup, the extension reads page text and inline script text in the active tab to calculate inspection signals. It sends the page URL, title, recent redirect URLs, password-field and form counts, external form-action and hidden-frame counts, and two indicators: whether page text contains credential-related wording and whether inline scripts match obfuscation patterns. The full page text, HTML, and script text are not included in that snapshot. The backend may also request the submitted public URL for its own page inspection.',
  },
  {
    icon: Database,
    title: 'Extension downloads and usage',
    body: 'When a browser download starts, the extension sends its source URL for scanning and sends the file name, MIME type, and size for a separate file check. This extension feature does not upload the downloaded file’s bytes. The extension also reports its client ID, version, and browser name when it starts and about every five minutes while running; the server records its latest contact time. If you create or pair a device, the service receives the device name you enter (when creating one), browser name, and pairing code. Extension ZIP download requests are counted in aggregate, including repeat requests.',
  },
  {
    icon: HardDrive,
    title: 'Data processed and stored',
    body: 'The backend processes submitted URLs, consented email sender/subject/body text, download metadata, and page-inspection signals to produce scan results. If you use the web app’s separate file scanner, the browser sends the file name, type, size, SHA-256 hash, and supported extracted text for analysis; it does not send the original file bytes. Saved records can include a client and scan ID, redacted target information, file hashes where available, verdicts, scores, evidence, timestamps, and methodology details. Search previews are not added to Scan History. Whether raw submitted scan content is saved depends on the server’s storage configuration. When content storage is disabled, raw email/message text and extracted uploaded-file text are not retained after analysis; when it is enabled, that content may be stored with the scan record. The current production setting has not been verified for this notice.',
  },
  {
    icon: LockKeyhole,
    title: 'Storage and access',
    body: 'The extension stores its random client ID and access token, search and email consent choices, settings such as the Gmail batch size, current scan status (which may include the last URL), and blocked-host information in Chrome extension storage on your device. The token is sent to the Tracking Threats backend to authenticate extension requests. The backend receives network request metadata, including the connecting IP address, and uses request IP for rate limiting; this notice does not verify Railway’s infrastructure log retention. Server-side scan records are associated with the browser client and are available through that client’s access controls. Stored content and the information administrators can access depend on server configuration; this notice does not assume that raw-content storage is disabled in production.',
  },
  {
    icon: ExternalLink,
    title: 'External providers',
    body: 'Depending on server configuration and scan type, reputation checks may share submitted URLs, extracted link URLs, domains, IP indicators, or file hashes with VirusTotal, Google Safe Browsing, URLhaus, PhishTank, AbuseIPDB, DNS services, MalwareBazaar, or MetaDefender. These integrations are conditional; this notice does not claim that any particular provider is currently active. If scan reports or history digests are enabled and configured, the report recipient and the configured SMTP service or Resend may receive report contents such as targets, results, timestamps, warnings, and recommendations. The application is hosted on Railway. External providers may process data under their own terms and in locations outside the Philippines.',
  },
  {
    icon: Trash2,
    title: 'Retention and deletion',
    body: 'Scan records, security audit logs, and inactive client records expire according to configurable server retention settings. The server code defaults are 30 days for scan records, 90 days for audit logs, and 180 days without relevant client activity for client credentials; deployment settings can change these periods, and the current production values have not been verified here. Clear History removes the current client’s scan history. Delete My Data removes server-side scan records and related evidence, audit records, and saved report-email settings, and revokes the browser credential. This does not clear data stored locally by the extension. To remove local extension data, remove Tracking Threats Browser Monitor from Chrome’s extension settings; this also disables its monitoring. Removing the extension does not itself delete server-side records.',
  },
]

export function PrivacyNotice({ embedded = false, onNavigate }) {
  return (
    <div className="space-y-6">
      {!embedded && (
        <header className="border-b border-slate-200 pb-5 dark:border-slate-800">
          <p className="text-sm font-medium text-teal-700 dark:text-teal-300">Privacy Notice 2026.12</p>
          <h1 className="mt-1 text-2xl font-semibold">How scan data is handled</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600 dark:text-slate-300">
            Tracking Threats scans eligible website URLs, search-result links, consented email, and
            download metadata for security threats. The information handled depends on the feature
            you use and the choices you make.
          </p>
        </header>
      )}

      {embedded && (
        <div>
          <p className="text-sm font-medium text-teal-700 dark:text-teal-300">Privacy Notice 2026.12</p>
          <h2 className="mt-1 text-xl font-semibold">How scan data is handled</h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600 dark:text-slate-300">
            Tracking Threats scans eligible website URLs, search-result links, consented email, and
            download metadata for security threats. The information handled depends on the feature
            you use and the choices you make.
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
            Search and email monitoring choices can be changed in their respective extension
            controls. You may clear scan history, remove notification recipients, or use Delete My
            Data in Settings to remove the server-side data associated with this browser client.
            The extension has no separate clear-all local-storage control; removing it in Chrome
            clears its local extension data and disables monitoring. For a correction or objection,
            contact the project team through the names shown in Settings. Do not submit content you
            are not authorized to process.
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
