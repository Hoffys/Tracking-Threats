import { useState } from 'react'
import { Download, Puzzle, X } from 'lucide-react'
import { chromeWebStoreUrl, extensionDownloadUrl } from '../services/api'

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
            <h2 className="text-lg font-semibold">Get the browser extension</h2>
            <button type="button" onClick={() => setOpen(false)} aria-label="Close extension setup"><X size={22} /></button>
          </div>
          <p className="mt-3">For desktop Chrome and Edge. Choose the Chrome Web Store for the simple install, or use the ZIP for manual setup.</p>
          {chromeWebStoreUrl ? (
            <a href={chromeWebStoreUrl} target="_blank" rel="noopener noreferrer" className="mt-4 inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-3 font-semibold text-white hover:bg-emerald-700">
              <Puzzle size={18} /> Add to Chrome
            </a>
          ) : (
            <p className="mt-4 rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-100">
              Chrome Web Store installation will appear here after the extension is published. For now, use the manual ZIP installation below.
            </p>
          )}
          <h3 className="mt-5 font-semibold">Manual installation</h3>
          <a href={extensionDownloadUrl} className="mt-2 inline-flex items-center gap-2 rounded-lg border border-emerald-600 px-4 py-3 font-semibold text-emerald-800 hover:bg-emerald-50 dark:text-emerald-200 dark:hover:bg-slate-800">
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
          <p className="mt-3">No Google account connection is needed. Search-result and email scanning each require your separate consent.</p>
          <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">We count ZIP download requests. The enabled extension reports its random client ID, version, and activity time about every 5 minutes so admins can monitor usage. Counts represent browser clients, not unique people.</p>
        </section>
      )}
    </div>
  )
}
