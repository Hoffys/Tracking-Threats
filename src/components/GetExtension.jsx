import { useState } from 'react'
import { Download, Puzzle, X } from 'lucide-react'
import { extensionDownloadUrl } from '../services/api'

export function GetExtension() {
  const [open, setOpen] = useState(false)
  return (
    <div className="relative">
      <button type="button" onClick={() => setOpen((value) => !value)} aria-expanded={open} aria-controls="extension-setup" className="inline-flex items-center gap-2 rounded-lg border border-emerald-400 px-3 py-2 text-sm font-semibold text-emerald-800 dark:text-emerald-200">
        <Puzzle size={17} /> Get Extension
      </button>
      {open && (
        <section id="extension-setup" className="fixed inset-x-4 top-24 z-50 mx-auto max-h-[75vh] max-w-lg overflow-y-auto rounded-xl border border-emerald-300 bg-white p-5 text-sm shadow-2xl dark:border-slate-600 dark:bg-slate-900">
          <div className="flex items-start justify-between gap-3">
            <h2 className="text-lg font-semibold">Download browser extension</h2>
            <button type="button" onClick={() => setOpen(false)} aria-label="Close extension setup"><X size={22} /></button>
          </div>
          <p className="mt-3">For desktop Chrome and Edge. This ZIP needs a one-time manual installation; it is not a browser store listing.</p>
          <a href={extensionDownloadUrl} className="mt-4 inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-3 font-semibold text-white hover:bg-emerald-700">
            <Download size={18} /> Download Extension ZIP
          </a>
          <ol className="mt-4 list-decimal space-y-3 pl-5">
            <li>Download the ZIP, then choose <strong>Extract All</strong>. Keep the extracted folder on your computer.</li>
            <li>In Chrome, open <code>chrome://extensions</code>. In Edge, open <code>edge://extensions</code>.</li>
            <li>Turn on <strong>Developer mode</strong> and click <strong>Load unpacked</strong>.</li>
            <li>Select the extracted <strong>tracking-threats-extension</strong> folder containing <code>manifest.json</code>.</li>
            <li>Pin Tracking Threats from the browser Extensions menu. It connects to this server automatically.</li>
            <li>Browse supported sites, then open the extension popup to view scan status and your linked history.</li>
          </ol>
          <p className="mt-4">Already installed? Replace the files in your existing extension folder with the extracted files, then click <strong>Reload</strong> on the extensions page.</p>
          <p className="mt-3">Installing the app is separate. No Google account connection is needed; email scanning requires your consent.</p>
          <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">We count ZIP download requests. The enabled extension reports its random client ID, version, and activity time about every 5 minutes so admins can monitor usage. Counts represent browser clients, not unique people.</p>
        </section>
      )}
    </div>
  )
}
