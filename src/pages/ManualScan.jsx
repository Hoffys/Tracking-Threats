import { useState } from 'react'
import { motion } from 'framer-motion'
import {
  AlertTriangle,
  CheckCircle2,
  FileText,
  Link2,
  MailWarning,
  SearchCheck,
  ShieldX,
} from 'lucide-react'
import { Panel } from '../components/Panel'
import { RiskBadge } from '../components/RiskBadge'
import { useThreats } from '../hooks/useThreats'

export function ManualScan() {
  const { createScan } = useThreats()
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('URL')
  const [message, setMessage] = useState('')
  const [selectedFile, setSelectedFile] = useState(null)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [isScanning, setIsScanning] = useState(false)

  const readFilePreview = (file) =>
    new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => resolve(String(reader.result ?? ''))
      reader.onerror = () => reject(reader.error)
      reader.readAsText(file.slice(0, 200 * 1024))
    })

  const submit = async (event) => {
    event.preventDefault()
    const scanTarget =
      scanType === 'URL'
        ? target
        : scanType === 'File'
          ? selectedFile?.name
          : target || message.slice(0, 56) || 'Manual message scan'
    setIsScanning(true)
    setError('')
    try {
      if (scanType === 'File') {
        if (!selectedFile) throw new Error('No file selected')
        const content = await readFilePreview(selectedFile)
        setResult(
          await createScan({
            type: 'File',
            target: selectedFile.name,
            fileName: selectedFile.name,
            mimeType: selectedFile.type,
            size: selectedFile.size,
            content,
          }),
        )
      } else {
        setResult(await createScan({ type: scanType, target: scanTarget, content: message }))
      }
    } catch {
      setResult(null)
      setError('Scan failed. Make sure the backend is running, then try again.')
    } finally {
      setIsScanning(false)
    }
  }

  return (
    <div className="grid gap-5 lg:grid-cols-[0.9fr_1.1fr]">
      <Panel>
        <p className="text-sm font-medium text-teal-700 dark:text-teal-300">Manual Scan</p>
        <h1 className="mt-1 text-2xl font-semibold">Scan a URL, message, or file</h1>
        <form className="mt-5 space-y-4" onSubmit={submit}>
          <div className="grid grid-cols-3 gap-2 rounded-lg bg-slate-100 p-1 dark:bg-slate-950">
            {[
              { type: 'URL', icon: Link2 },
              { type: 'Message', icon: MailWarning },
              { type: 'File', icon: FileText },
            ].map(({ type, icon: Icon }) => (
              <button
                key={type}
                type="button"
                onClick={() => {
                  setScanType(type)
                  setResult(null)
                }}
                className={`inline-flex items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium ${
                  scanType === type
                    ? 'bg-white text-slate-950 shadow-sm dark:bg-slate-800 dark:text-white'
                    : 'text-slate-500 dark:text-slate-400'
                }`}
              >
                <Icon size={16} />
                {type}
              </button>
            ))}
          </div>
          {scanType !== 'File' && (
            <label className="block">
              <span className="text-sm font-medium">
                {scanType === 'URL' ? 'URL to scan' : 'Sender or subject'}
              </span>
              {scanType === 'URL' ? (
                <input
                  className="mt-2 w-full rounded-lg border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-teal-500 dark:border-slate-800 dark:bg-slate-950"
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                  placeholder="https://example.com/login"
                  required
                />
              ) : (
                <input
                  className="mt-2 w-full rounded-lg border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-teal-500 dark:border-slate-800 dark:bg-slate-950"
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                  placeholder="billing@example.com or Invoice notice"
                />
              )}
            </label>
          )}
          {scanType === 'File' && (
            <label className="block">
              <span className="text-sm font-medium">File to scan</span>
              <input
                className="mt-2 w-full rounded-lg border border-slate-200 bg-white px-3 py-3 text-sm outline-none file:mr-3 file:rounded-md file:border-0 file:bg-teal-600 file:px-3 file:py-2 file:text-sm file:font-semibold file:text-white focus:border-teal-500 dark:border-slate-800 dark:bg-slate-950"
                type="file"
                onChange={(event) => {
                  setSelectedFile(event.target.files?.[0] ?? null)
                  setResult(null)
                }}
                required
              />
              {selectedFile && (
                <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                  {selectedFile.name} • {(selectedFile.size / 1024).toFixed(1)} KB
                </p>
              )}
            </label>
          )}
          {scanType === 'Message' && (
            <label className="block">
              <span className="text-sm font-medium">Email or message content</span>
              <textarea
                className="mt-2 min-h-40 w-full rounded-lg border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-teal-500 dark:border-slate-800 dark:bg-slate-950"
                value={message}
                onChange={(event) => setMessage(event.target.value)}
                placeholder="Paste the suspicious email, SMS, or chat message here..."
                required
              />
            </label>
          )}
          <button
            className="inline-flex items-center gap-2 rounded-lg bg-teal-600 px-4 py-3 text-sm font-semibold text-white"
            type="submit"
            disabled={isScanning}
          >
            <SearchCheck size={18} />
            {isScanning ? 'Scanning...' : 'Run Scan'}
          </button>
        </form>
      </Panel>

      <Panel>
        <h2 className="text-lg font-semibold">Scan output</h2>
        {error ? (
          <div className="mt-4 rounded-lg border border-rose-500/40 bg-rose-500/10 p-4 text-sm font-medium text-rose-700 dark:text-rose-300">
            {error}
          </div>
        ) : result ? (
          <div className="mt-4 space-y-4">
            {result.blocked && (
              <div className="rounded-lg border border-rose-500/40 bg-rose-600 p-4 text-white shadow-sm">
                <div className="flex items-start gap-3">
                  <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-white/15">
                    <ShieldX size={21} />
                  </span>
                  <div>
                    <p className="font-semibold">Threat Blocked Automatically</p>
                    <p className="mt-1 text-sm text-rose-50">
                      This Dangerous scan was marked as Blocked and saved to flagged threats.
                    </p>
                  </div>
                </div>
              </div>
            )}
          <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-800">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <p className="truncate font-medium">{result.target}</p>
                <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                  {result.type} • Safety score {result.score}/100
                </p>
                {result.responseStatus && (
                  <p className="mt-1 text-sm font-semibold text-rose-600 dark:text-rose-300">
                    Response: {result.responseStatus}
                  </p>
                )}
              </div>
              <RiskBadge risk={result.status ?? result.risk} />
            </div>
            <div className="mt-5 h-3 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
              <motion.div
                initial={{ width: 0 }}
                animate={{
                  width: `${result.score}%`,
                  boxShadow: [
                    '0 0 0 rgba(20,184,166,0)',
                    '0 0 16px rgba(20,184,166,0.45)',
                    '0 0 0 rgba(20,184,166,0)',
                  ],
                }}
                transition={{
                  width: { duration: 0.7, ease: 'easeOut' },
                  boxShadow: { duration: 1.8, repeat: Infinity, ease: 'easeInOut' },
                }}
                className={`h-3 rounded-full ${
                  result.status === 'Dangerous'
                    ? 'bg-rose-500'
                    : result.status === 'Suspicious'
                      ? 'bg-amber-500'
                      : 'bg-emerald-500'
                }`}
              />
            </div>
            <p className="mt-4 text-sm text-slate-600 dark:text-slate-300">
              {result.summary}
            </p>
            <div className="mt-5 grid gap-4 md:grid-cols-2">
              <div>
                <div className="mb-2 flex items-center gap-2 text-sm font-semibold">
                  <AlertTriangle size={17} className="text-amber-500" />
                  Warning signs
                </div>
                {result.warningSigns?.length > 0 ? (
                  <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-300">
                    {result.warningSigns.map((sign) => (
                      <li key={sign}>- {sign}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-slate-500 dark:text-slate-400">
                    No warning signs detected.
                  </p>
                )}
              </div>
              <div>
                <div className="mb-2 flex items-center gap-2 text-sm font-semibold">
                  <CheckCircle2 size={17} className="text-teal-500" />
                  Recommendations
                </div>
                <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-300">
                  {(result.recommendations ?? [result.recommendation]).map((recommendation) => (
                    <li key={recommendation}>- {recommendation}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
          </div>
        ) : (
          <p className="mt-4 text-sm text-slate-500 dark:text-slate-400">
            Submit a URL, message, or file to generate a backend-powered 0-100 safety score.
          </p>
        )}
      </Panel>
    </div>
  )
}
