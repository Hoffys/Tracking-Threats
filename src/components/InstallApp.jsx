import { useEffect, useState } from 'react'
import { Download, CheckCircle2 } from 'lucide-react'

export function InstallApp() {
  const [prompt, setPrompt] = useState(null)
  const [installed, setInstalled] = useState(() =>
    window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true)
  const [showHelp, setShowHelp] = useState(false)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  useEffect(() => {
    const onPrompt = (event) => { event.preventDefault(); setPrompt(event) }
    const onInstalled = () => { setInstalled(true); setPrompt(null); setShowHelp(false) }
    const media = window.matchMedia('(display-mode: standalone)')
    const onDisplay = () => setInstalled(media.matches || navigator.standalone === true)
    window.addEventListener('beforeinstallprompt', onPrompt)
    window.addEventListener('appinstalled', onInstalled)
    media.addEventListener('change', onDisplay)
    return () => {
      window.removeEventListener('beforeinstallprompt', onPrompt)
      window.removeEventListener('appinstalled', onInstalled)
      media.removeEventListener('change', onDisplay)
    }
  }, [])

  const install = async () => {
    if (!prompt) { setShowHelp((value) => !value); return }
    setBusy(true)
    setMessage('')
    try {
      await prompt.prompt()
      const choice = await prompt.userChoice
      setMessage(choice.outcome === 'accepted'
        ? 'Installation requested. Open Tracking Threats from your app launcher once it finishes.'
        : 'Installation canceled. You can keep using the website.')
    } catch {
      setMessage('Use your browser menu to install the app.')
      setShowHelp(true)
    } finally {
      setPrompt(null)
      setBusy(false)
    }
  }

  return (
    <div className="relative">
      {installed ? (
        <span className="inline-flex items-center gap-2 text-sm text-emerald-700 dark:text-emerald-300"><CheckCircle2 size={17} /> App installed</span>
      ) : (
        <button type="button" onClick={install} disabled={busy} aria-expanded={showHelp} aria-controls="install-app-help" className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-3 py-2 text-sm font-semibold text-white hover:bg-emerald-700 disabled:opacity-50">
          <Download size={17} /> {busy ? 'Opening installer…' : 'Install App'}
        </button>
      )}
      {message && <p role="status" className="mt-2 max-w-xs text-xs">{message}</p>}
      {showHelp && (
        <div id="install-app-help" className="absolute right-0 z-40 mt-3 w-72 max-w-[85vw] space-y-3 rounded-lg border border-emerald-200 bg-white p-4 text-sm shadow-xl dark:border-slate-700 dark:bg-slate-900">
          <h2 className="font-semibold">Install Tracking Threats</h2>
          <p>Chrome: open the browser menu, then Cast, save, and share → Install page as app. You may also see an install icon in the address bar.</p>
          <p>Edge: browser menu → Apps → Install this site as an app.</p>
          <p>iPhone/iPad: open in Safari → Share → Add to Home Screen.</p>
          <p>If already installed, open Tracking Threats from your app launcher. Scanning requires an internet connection.</p>
          <p>The browser extension is installed separately in your desktop browser. Installing this app does not install the extension.</p>
          <button type="button" onClick={() => setShowHelp(false)} className="font-semibold text-emerald-700 dark:text-emerald-300">Close instructions</button>
        </div>
      )}
    </div>
  )
}
