import { useState } from 'react'
import { motion } from 'framer-motion'
import {
  AlertTriangle,
  CheckCircle2,
  FileText,
  Link2,
  MailCheck,
  MailWarning,
  SearchCheck,
  ShieldX,
  TextSearch,
  UserRoundCheck,
} from 'lucide-react'
import { Panel } from '../components/Panel'
import { RiskBadge } from '../components/RiskBadge'
import { ThreatIntelSummary } from '../components/ThreatIntelSummary'
import { useThreats } from '../hooks/useThreats'

export function ManualScan() {
  const { createScan } = useThreats()
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('URL')
  const [message, setMessage] = useState('')
  const [emailSender, setEmailSender] = useState('')
  const [emailSubject, setEmailSubject] = useState('')
  const [emailBody, setEmailBody] = useState('')
  const [selectedFiles, setSelectedFiles] = useState([])
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [isScanning, setIsScanning] = useState(false)
  const scanTypeLabels = {
    URL: 'URL',
    Email: 'Email',
    Message: 'SMS',
    File: 'File',
  }

  const readFilePreview = (file) =>
    new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => resolve(String(reader.result ?? ''))
      reader.onerror = () => reject(reader.error)
      reader.readAsText(file.slice(0, 200 * 1024))
    })

  const hashFile = async (file) => {
    const buffer = await file.arrayBuffer()
    const digest = await crypto.subtle.digest('SHA-256', buffer)
    return Array.from(new Uint8Array(digest))
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('')
  }

  const selectScanType = (type) => {
    setScanType(type)
    setResult(null)
    setError('')
  }

  const submit = async (event) => {
    event.preventDefault()
    const scanTarget =
      scanType === 'URL'
        ? target
        : scanType === 'File'
          ? selectedFiles.map((file) => file.name).join(', ')
          : scanType === 'Email'
            ? emailSubject || emailSender || 'Email content without sender or subject'
          : target || message.slice(0, 56) || 'Manual SMS scan'

    setIsScanning(true)
    setError('')

    try {
      if (scanType === 'File') {
        if (selectedFiles.length === 0) throw new Error('No file selected')
        const scans = await Promise.all(
          selectedFiles.map(async (selectedFile) => {
            const [content, sha256] = await Promise.all([
              readFilePreview(selectedFile),
              hashFile(selectedFile),
            ])
            return createScan({
              type: 'File',
              target: selectedFile.name,
              fileName: selectedFile.name,
              mimeType: selectedFile.type,
              size: selectedFile.size,
              content,
              sha256,
            })
          }),
        )
        setResult(scans)
      } else if (scanType === 'Email') {
        setResult(
          await createScan({
            type: 'Email',
            target: scanTarget,
            sender: emailSender,
            subject: emailSubject,
            body: emailBody,
            content: `${emailSubject}\n${emailBody}`.trim(),
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

  const scanResults = (Array.isArray(result) ? result : [result]).filter(Boolean)
  const scanButtonText =
    isScanning && scanType === 'File'
      ? `Scanning ${selectedFiles.length} file${selectedFiles.length === 1 ? '' : 's'}...`
      : isScanning
        ? 'Scanning...'
        : scanType === 'File' && selectedFiles.length > 1
          ? `Run ${selectedFiles.length} File Scans`
          : 'Run Scan'

  const renderScanResult = (scanResult) => (
    <div key={scanResult.id} className="space-y-4">
      {scanResult.blocked && (
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
            <p className="truncate font-medium">{scanResult.target}</p>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
              {scanResult.type} - Safety score {scanResult.score}/100
            </p>
            {scanResult.responseStatus && (
              <p className="mt-1 text-sm font-semibold text-rose-600 dark:text-rose-300">
                Response: {scanResult.responseStatus}
              </p>
            )}
          </div>
          <RiskBadge risk={scanResult.status ?? scanResult.risk} />
        </div>

        <div className="mt-5 h-3 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
          <motion.div
            initial={{ width: 0 }}
            animate={{
              width: `${scanResult.score}%`,
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
              scanResult.status === 'Dangerous'
                ? 'bg-rose-500'
                : scanResult.status === 'Suspicious'
                  ? 'bg-amber-500'
                  : 'bg-emerald-500'
            }`}
          />
        </div>

        <p className="mt-4 text-sm text-slate-600 dark:text-slate-300">
          {scanResult.summary}
        </p>
        <ThreatIntelSummary providers={scanResult.threatIntel} />

        {scanResult.fileDetails?.sha256 && (
          <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-950">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
              SHA-256
            </p>
            <p className="mt-1 break-all font-mono text-xs text-slate-700 dark:text-slate-200">
              {scanResult.fileDetails.sha256}
            </p>
          </div>
        )}

        {renderEmailBreakdown(scanResult.emailBreakdown)}

        <div className="mt-5 grid gap-4 md:grid-cols-2">
          <div>
            <div className="mb-2 flex items-center gap-2 text-sm font-semibold">
              <AlertTriangle size={17} className="text-amber-500" />
              Warning signs
            </div>
            {scanResult.warningSigns?.length > 0 ? (
              <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-300">
                {scanResult.warningSigns.map((sign) => (
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
              {(scanResult.recommendations ?? [scanResult.recommendation]).map(
                (recommendation) => (
                  <li key={recommendation}>- {recommendation}</li>
                ),
              )}
            </ul>
          </div>
        </div>
      </div>
    </div>
  )

  const renderEmailBreakdown = (breakdown) => {
    if (!breakdown) return null

    const panels = [
      { key: 'sender', title: 'Sender risk', icon: UserRoundCheck },
      { key: 'content', title: 'Content risk', icon: TextSearch },
      { key: 'links', title: 'Link risk', icon: Link2 },
    ]

    return (
      <div className="mt-5 grid gap-3 lg:grid-cols-3">
        {panels.map(({ key, title, icon: Icon }) => {
          const analysis = breakdown[key]
          if (!analysis) return null
          const warnings = analysis.warningSigns ?? []

          return (
            <div key={key} className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
              <div className="mb-3 flex items-start justify-between gap-3">
                <div className="flex min-w-0 items-center gap-2">
                  <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-200">
                    <Icon size={17} />
                  </span>
                  <div className="min-w-0">
                    <p className="text-sm font-semibold">{title}</p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Score {analysis.score}/100
                    </p>
                  </div>
                </div>
                <RiskBadge risk={analysis.status} />
              </div>
              {key === 'links' && analysis.extracted?.length > 0 && (
                <div className="mb-2 space-y-1">
                  {analysis.extracted.slice(0, 3).map((link) => (
                    <p
                      key={link}
                      className="truncate rounded-md bg-slate-100 px-2 py-1 text-xs text-slate-600 dark:bg-slate-950 dark:text-slate-300"
                    >
                      {link}
                    </p>
                  ))}
                </div>
              )}
              {warnings.length > 0 ? (
                <ul className="space-y-1 text-sm text-slate-600 dark:text-slate-300">
                  {warnings.map((warning) => (
                    <li key={warning}>- {warning}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-slate-500 dark:text-slate-400">
                  No strong indicators detected.
                </p>
              )}
            </div>
          )
        })}
      </div>
    )
  }

  return (
    <div className="grid gap-5 lg:grid-cols-[0.9fr_1.1fr]">
      <Panel>
        <p className="text-sm font-medium text-teal-700 dark:text-teal-300">Manual Scan</p>
        <h1 className="mt-1 text-2xl font-semibold">Scan a URL, email, SMS, or file</h1>
        <form className="mt-5 space-y-4" onSubmit={submit}>
          <div className="grid grid-cols-2 gap-2 rounded-lg bg-slate-100 p-1 dark:bg-slate-950 sm:grid-cols-4">
            {[
              { type: 'URL', icon: Link2 },
              { type: 'Email', icon: MailCheck },
              { type: 'Message', icon: MailWarning },
              { type: 'File', icon: FileText },
            ].map(({ type, icon: Icon }) => (
              <button
                key={type}
                type="button"
                onClick={() => selectScanType(type)}
                className={`inline-flex items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium ${
                  scanType === type
                    ? 'bg-white text-slate-950 shadow-sm dark:bg-slate-800 dark:text-white'
                    : 'text-slate-500 dark:text-slate-400'
                }`}
              >
                <Icon size={16} />
                {scanTypeLabels[type]}
              </button>
            ))}
          </div>

          {scanType !== 'File' && scanType !== 'Email' && (
            <label className="block">
              <span className="text-sm font-medium">
                {scanType === 'URL' ? 'URL to scan' : 'Sender or subject'}
              </span>
              <input
                className="mt-2 w-full rounded-lg border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-teal-500 dark:border-slate-800 dark:bg-slate-950"
                value={target}
                onChange={(event) => {
                  setTarget(event.target.value)
                  setResult(null)
                }}
                placeholder={
                  scanType === 'URL'
                    ? 'https://example.com/login'
                    : 'Paste a phone number, sender name, or suspicious SMS'
                }
                required={scanType === 'URL'}
              />
            </label>
          )}

          {scanType === 'Email' && (
            <div className="space-y-4">
              <label className="block">
                <span className="text-sm font-medium">Sender</span>
                <input
                  className="mt-2 w-full rounded-lg border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-teal-500 dark:border-slate-800 dark:bg-slate-950"
                  value={emailSender}
                  onChange={(event) => {
                    setEmailSender(event.target.value)
                    setResult(null)
                  }}
                  placeholder="security@example.com"
                />
              </label>
              <label className="block">
                <span className="text-sm font-medium">Subject</span>
                <input
                  className="mt-2 w-full rounded-lg border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-teal-500 dark:border-slate-800 dark:bg-slate-950"
                  value={emailSubject}
                  onChange={(event) => {
                    setEmailSubject(event.target.value)
                    setResult(null)
                  }}
                  placeholder="Action required"
                />
              </label>
              <label className="block">
                <span className="text-sm font-medium">Email body</span>
                <textarea
                  className="mt-2 min-h-44 w-full rounded-lg border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-teal-500 dark:border-slate-800 dark:bg-slate-950"
                  value={emailBody}
                  onChange={(event) => {
                    setEmailBody(event.target.value)
                    setResult(null)
                  }}
                  placeholder="Paste email content here..."
                  required
                />
              </label>
            </div>
          )}

          {scanType === 'File' && (
            <label className="block">
              <span className="text-sm font-medium">File to scan</span>
              <input
                className="mt-2 w-full rounded-lg border border-slate-200 bg-white px-3 py-3 text-sm outline-none file:mr-3 file:rounded-md file:border-0 file:bg-teal-600 file:px-3 file:py-2 file:text-sm file:font-semibold file:text-white focus:border-teal-500 dark:border-slate-800 dark:bg-slate-950"
                type="file"
                multiple
                onChange={(event) => {
                  setSelectedFiles(Array.from(event.target.files ?? []))
                  setResult(null)
                }}
                required
              />
              {selectedFiles.length > 0 && (
                <div className="mt-3 rounded-lg border border-slate-200 p-3 dark:border-slate-800">
                  <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                    {selectedFiles.length} file{selectedFiles.length === 1 ? '' : 's'} selected
                  </p>
                  <ul className="mt-2 max-h-32 space-y-1 overflow-auto text-xs text-slate-500 dark:text-slate-400">
                    {selectedFiles.map((file) => (
                      <li key={`${file.name}-${file.lastModified}`}>
                        {file.name} - {(file.size / 1024).toFixed(1)} KB
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </label>
          )}

          {scanType === 'Message' && (
            <label className="block">
              <span className="text-sm font-medium">SMS content</span>
              <textarea
                className="mt-2 min-h-40 w-full rounded-lg border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-teal-500 dark:border-slate-800 dark:bg-slate-950"
                value={message}
                onChange={(event) => {
                  setMessage(event.target.value)
                  setResult(null)
                }}
                placeholder="Paste the suspicious SMS here..."
                required
              />
            </label>
          )}

          <button
            className="inline-flex items-center gap-2 rounded-lg bg-teal-600 px-4 py-3 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-70"
            type="submit"
            disabled={isScanning}
          >
            <SearchCheck size={18} />
            {scanButtonText}
          </button>
        </form>
      </Panel>

      <Panel>
        <h2 className="text-lg font-semibold">Scan output</h2>
        {error ? (
          <div className="mt-4 rounded-lg border border-rose-500/40 bg-rose-500/10 p-4 text-sm font-medium text-rose-700 dark:text-rose-300">
            {error}
          </div>
        ) : scanResults.length > 0 ? (
          <div className="mt-4 space-y-4">
            {scanResults.length > 1 && (
              <p className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm font-medium text-slate-600 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300">
                Completed {scanResults.length} file scans.
              </p>
            )}
            {scanResults.map(renderScanResult)}
          </div>
        ) : (
          <p className="mt-4 text-sm text-slate-500 dark:text-slate-400">
            Submit a URL, SMS, or file to generate a backend-powered 0-100 safety score.
          </p>
        )}
      </Panel>
    </div>
  )
}
