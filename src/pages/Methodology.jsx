import { useMemo, useState } from 'react'
import {
  BookOpenCheck,
  Database,
  FileSearch,
  FlaskConical,
  Search,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react'

const processSteps = [
  ['1', 'Intake', 'Validate the scan type and required input, then assign a random scan ID.'],
  ['2', 'Minimize', 'Use raw content only for analysis. Public deployments retain metadata and results, not raw bodies or file text.'],
  ['3', 'Local rules', 'Evaluate URL structure, sender patterns, message language, links, file names, extensions, and script indicators.'],
  ['4', 'Reputation', 'Query configured providers for URL or SHA-256 reputation. Provider errors do not become threat matches.'],
  ['5', 'Score', 'Start at 100, apply documented deductions, and map the result to Safe, Caution, or Dangerous.'],
  ['6', 'Evidence', 'Save the result, matched rules, provider findings, methodology version, retention date, and audit metadata.'],
  ['7', 'Response', 'Allow, request review, or block. A result reports indicators and never guarantees authenticity.'],
]

const rules = [
  ['URL', 'Missing or malformed URL', 18],
  ['URL', 'URL does not use HTTPS', 16],
  ['URL', 'Punycode domain', 24],
  ['URL', 'Multiple domain hyphens', 12],
  ['URL', 'Mixed letters and numbers', 10],
  ['URL', 'Account, login, verification, or reward wording', 18],
  ['URL', 'Known piracy or torrent domain', 55],
  ['URL', 'Gambling or betting domain', 45],
  ['URL', 'Suspicious top-level domain', 18],
  ['URL', 'IP address used as host', 25],
  ['URL', 'URL shortener', 20],
  ['URL', 'Possible brand typosquatting', 25],
  ['Email', 'Sender has no valid domain', 24],
  ['Email', 'Lookalike brand spelling', 22],
  ['Email', 'Official-sounding free-mail sender', 14],
  ['Message', 'Urgency or pressure language', 16],
  ['Message', 'Financial or identity-information request', 20],
  ['Message', 'Password or login request', 22],
  ['Message', 'Prize or lottery language', 16],
  ['Message', 'Contains an unverified link', 10],
  ['File', 'No visible extension', 12],
  ['File', 'Executable extension', 34],
  ['File', 'Macro-enabled Office extension', 24],
  ['File', 'Misleading double extension', 28],
  ['File', 'Macro or script execution text', 30],
  ['File', 'Dangerous phishing language in extracted text', 24],
  ['Provider', 'VirusTotal malicious URL detection', 55],
  ['Provider', 'VirusTotal suspicious URL detection', 25],
  ['Provider', 'Verified active PhishTank entry', 60],
  ['Provider', 'Google Safe Browsing threat match', 60],
  ['Provider', 'URLhaus URL listing', 65],
  ['Provider', 'VirusTotal malicious file-hash detection', 65],
]

const providers = [
  ['VirusTotal', 'URL and SHA-256 reputation', 'A match requires at least one malicious or suspicious engine detection.'],
  ['Google Safe Browsing', 'Known web threats', 'A match requires a returned threat entry.'],
  ['URLhaus', 'Malware URLs and hosts', 'A match requires an active database result.'],
  ['PhishTank', 'Community phishing reports', 'A match requires an in-database, verified, and valid entry.'],
  ['AbuseIPDB', 'Host IP reputation', 'Confidence is supporting evidence; it does not prove the page itself is malicious.'],
  ['DNS', 'Public address resolution', 'Missing or private address results are structural warnings, not identity proof.'],
]

const documentChecks = [
  'SHA-256 is calculated from the entire selected file.',
  'File name, extension, double extension, size, and MIME metadata are reviewed.',
  'The first 200 KB is read as text for phishing, macro, script, and embedded-link indicators.',
  'The SHA-256 hash is checked with VirusTotal when configured.',
  'The original file is not retained when STORE_SCAN_CONTENT=false.',
]

const limitations = [
  'Safe means no configured indicator was found; it does not prove ownership, identity, or authenticity.',
  'The scanner does not execute files in a malware sandbox.',
  'It does not currently validate PDF or Office digital signatures or certificate chains.',
  'It does not perform full binary parsing, OCR, or forensic document examination.',
  'External providers can be unavailable, delayed, incomplete, or wrong.',
  'Important contracts, IDs, invoices, and certificates must be confirmed with the issuing organization.',
]

export function Methodology({ embedded = false }) {
  const [activeTab, setActiveTab] = useState('process')
  const [query, setQuery] = useState('')
  const filteredRules = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    return normalized
      ? rules.filter(([group, rule]) => `${group} ${rule}`.toLowerCase().includes(normalized))
      : rules
  }, [query])

  const tabs = [
    ['process', 'Process'],
    ['rules', 'Rule library'],
    ['providers', 'Providers'],
    ['documents', 'Documents'],
    ['limits', 'Limitations'],
  ]

  return (
    <div className="space-y-5">
      {!embedded && (
        <header className="border-b border-slate-200 pb-5 dark:border-slate-800">
          <p className="text-sm font-medium text-teal-700 dark:text-teal-300">Methodology 2026.09</p>
          <h1 className="mt-1 text-2xl font-semibold">How Tracking Threats reaches a verdict</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600 dark:text-slate-300">
            This library documents the active process, evidence sources, score deductions, and known
            limitations used for URL, email, message, and file scans.
          </p>
        </header>
      )}

      {embedded && (
        <div>
          <p className="text-sm font-medium text-teal-700 dark:text-teal-300">Methodology 2026.09</p>
          <h2 className="mt-1 text-xl font-semibold">How Tracking Threats reaches a verdict</h2>
        </div>
      )}

      <div className="flex gap-1 overflow-x-auto border-b border-slate-200 dark:border-slate-800" role="tablist">
        {tabs.map(([id, label]) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={activeTab === id}
            onClick={() => setActiveTab(id)}
            className={`shrink-0 border-b-2 px-3 py-3 text-sm font-semibold ${
              activeTab === id
                ? 'border-teal-500 text-teal-700 dark:text-teal-300'
                : 'border-transparent text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {activeTab === 'process' && (
        <section>
          <div className="mb-4 flex items-center gap-2">
            <FlaskConical size={19} className="text-teal-500" />
            <h2 className="text-lg font-semibold">Scan lifecycle</h2>
          </div>
          <ol className="divide-y divide-slate-200 border-y border-slate-200 dark:divide-slate-800 dark:border-slate-800">
            {processSteps.map(([number, title, detail]) => (
              <li key={number} className="grid gap-3 py-4 sm:grid-cols-[48px_150px_1fr] sm:items-start">
                <span className="grid h-9 w-9 place-items-center rounded-lg bg-teal-600 text-sm font-semibold text-white">{number}</span>
                <strong className="text-sm">{title}</strong>
                <p className="text-sm leading-6 text-slate-600 dark:text-slate-300">{detail}</p>
              </li>
            ))}
          </ol>
          <div className="mt-5 grid gap-3 sm:grid-cols-3">
            {[
              ['Safe', '80-100', 'Allowed'],
              ['Caution', '51-79', 'Review'],
              ['Dangerous', '0-50', 'Blocked'],
            ].map(([label, range, action]) => (
              <div key={label} className="rounded-lg border border-slate-200 p-4 dark:border-slate-800">
                <p className="text-sm font-semibold">{label}</p>
                <p className="mt-2 text-2xl font-semibold">{range}</p>
                <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Response: {action}</p>
              </div>
            ))}
          </div>
        </section>
      )}

      {activeTab === 'rules' && (
        <section>
          <label className="relative block max-w-xl">
            <Search size={17} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              className="w-full rounded-lg border border-slate-200 bg-white py-3 pl-10 pr-3 text-sm outline-none focus:border-teal-500 dark:border-slate-800 dark:bg-slate-950"
              placeholder="Search active rules"
            />
          </label>
          <div className="mt-4 overflow-x-auto border-y border-slate-200 dark:border-slate-800">
            <table className="w-full min-w-[620px] text-left text-sm">
              <thead className="bg-slate-100 text-xs uppercase text-slate-500 dark:bg-slate-900 dark:text-slate-400">
                <tr><th className="px-3 py-3">Group</th><th className="px-3 py-3">Finding</th><th className="px-3 py-3 text-right">Maximum deduction</th></tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {filteredRules.map(([group, rule, deduction]) => (
                  <tr key={`${group}-${rule}`}><td className="px-3 py-3 font-semibold">{group}</td><td className="px-3 py-3 text-slate-600 dark:text-slate-300">{rule}</td><td className="px-3 py-3 text-right font-semibold">-{deduction}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {activeTab === 'providers' && (
        <section className="divide-y divide-slate-200 border-y border-slate-200 dark:divide-slate-800 dark:border-slate-800">
          {providers.map(([name, coverage, meaning]) => (
            <article key={name} className="grid gap-2 py-4 md:grid-cols-[190px_220px_1fr]">
              <h2 className="font-semibold">{name}</h2><p className="text-sm text-slate-500 dark:text-slate-400">{coverage}</p><p className="text-sm leading-6 text-slate-600 dark:text-slate-300">{meaning}</p>
            </article>
          ))}
        </section>
      )}

      {activeTab === 'documents' && (
        <section className="grid gap-5 lg:grid-cols-[1fr_0.8fr]">
          <div>
            <div className="flex items-center gap-2"><FileSearch size={19} className="text-teal-500" /><h2 className="text-lg font-semibold">Current file process</h2></div>
            <ol className="mt-4 divide-y divide-slate-200 border-y border-slate-200 dark:divide-slate-800 dark:border-slate-800">
              {documentChecks.map((check, index) => <li key={check} className="flex gap-3 py-3 text-sm leading-6"><span className="font-semibold text-teal-600">{index + 1}</span><span>{check}</span></li>)}
            </ol>
          </div>
          <div className="rounded-lg border border-amber-400/50 bg-amber-50 p-4 dark:bg-amber-950/20">
            <TriangleAlert size={20} className="text-amber-600" />
            <h2 className="mt-3 font-semibold">Authenticity is a separate question</h2>
            <p className="mt-2 text-sm leading-6 text-slate-700 dark:text-slate-300">A malware-free document can still be forged or misleading. Confirm important documents with the issuer or verify a trusted digital signature.</p>
          </div>
        </section>
      )}

      {activeTab === 'limits' && (
        <section>
          <div className="flex items-center gap-2"><BookOpenCheck size={19} className="text-teal-500" /><h2 className="text-lg font-semibold">Interpret results carefully</h2></div>
          <ul className="mt-4 divide-y divide-slate-200 border-y border-slate-200 dark:divide-slate-800 dark:border-slate-800">
            {limitations.map((item) => <li key={item} className="flex gap-3 py-3 text-sm leading-6"><ShieldCheck size={17} className="mt-1 shrink-0 text-teal-500" />{item}</li>)}
          </ul>
        </section>
      )}

      <footer className="flex items-center gap-3 border-t border-slate-200 pt-4 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
        <Database size={16} /> Each completed result is stored with methodology version 2026.09 and its supporting evidence.
      </footer>
    </div>
  )
}
