import { useState } from 'react'
import { Link2, MailCheck, ShieldAlert, TextSearch, UserRoundCheck } from 'lucide-react'
import { Panel } from '../components/Panel'
import { RiskBadge } from '../components/RiskBadge'
import { useThreats } from '../hooks/useThreats'

function RiskPanel({ icon: Icon, title, analysis, children }) {
  return (
    <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
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
      {children}
    </div>
  )
}

export function EmailAnalyzer() {
  const { createScan } = useThreats()
  const [sender, setSender] = useState('')
  const [subject, setSubject] = useState('')
  const [body, setBody] = useState('')
  const [result, setResult] = useState(null)
  const [isScanning, setIsScanning] = useState(false)

  const submit = async (event) => {
    event.preventDefault()
    setIsScanning(true)
    try {
      const scan = await createScan({
        type: 'Email',
        target: sender || subject || 'Untitled email',
        content: `${subject}\n${body}`,
      })
      setResult(scan)
    } finally {
      setIsScanning(false)
    }
  }

  return (
    <div className="grid gap-5 lg:grid-cols-[1.2fr_0.8fr]">
      <Panel>
        <p className="text-sm font-medium text-teal-700 dark:text-teal-300">Email Analyzer</p>
        <h1 className="mt-1 text-2xl font-semibold">Inspect a suspicious message</h1>

        <form className="mt-5 space-y-4" onSubmit={submit}>
          <label className="block">
            <span className="text-sm font-medium">Sender</span>
            <input
              className="mt-2 w-full rounded-lg border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-teal-500 dark:border-slate-800 dark:bg-slate-950"
              value={sender}
              onChange={(event) => setSender(event.target.value)}
              placeholder="security@example.com"
            />
          </label>
          <label className="block">
            <span className="text-sm font-medium">Subject</span>
            <input
              className="mt-2 w-full rounded-lg border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-teal-500 dark:border-slate-800 dark:bg-slate-950"
              value={subject}
              onChange={(event) => setSubject(event.target.value)}
              placeholder="Action required"
            />
          </label>
          <label className="block">
            <span className="text-sm font-medium">Email body</span>
            <textarea
              className="mt-2 min-h-44 w-full rounded-lg border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-teal-500 dark:border-slate-800 dark:bg-slate-950"
              value={body}
              onChange={(event) => setBody(event.target.value)}
              placeholder="Paste email content here..."
              required
            />
          </label>
          <button
            className="inline-flex items-center gap-2 rounded-lg bg-teal-600 px-4 py-3 text-sm font-semibold text-white"
            type="submit"
            disabled={isScanning}
          >
            <MailCheck size={18} />
            {isScanning ? 'Analyzing...' : 'Analyze Email'}
          </button>
        </form>
      </Panel>

      <Panel>
        <h2 className="text-lg font-semibold">Result</h2>
        {result ? (
          <div className="mt-4 space-y-4">
            <RiskBadge risk={result.status ?? result.risk} />
            <div>
              <p className="text-4xl font-semibold">{result.score}/100</p>
              <p className="text-sm text-slate-500 dark:text-slate-400">Final risk score</p>
            </div>
            <p className="text-sm text-slate-500 dark:text-slate-400">{result.summary}</p>

            {result.emailBreakdown && (
              <div className="space-y-3">
                <RiskPanel
                  icon={UserRoundCheck}
                  title="Sender risk"
                  analysis={result.emailBreakdown.sender}
                >
                  <p className="mb-2 text-xs text-slate-500 dark:text-slate-400">
                    Domain: {result.emailBreakdown.sender.domain}
                  </p>
                  {result.emailBreakdown.sender.warningSigns.length > 0 ? (
                    <ul className="space-y-1 text-sm text-slate-600 dark:text-slate-300">
                      {result.emailBreakdown.sender.warningSigns.map((warning) => (
                        <li key={warning}>- {warning}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-sm text-slate-500 dark:text-slate-400">
                      Sender domain looks normal.
                    </p>
                  )}
                </RiskPanel>

                <RiskPanel
                  icon={TextSearch}
                  title="Content risk"
                  analysis={result.emailBreakdown.content}
                >
                  {result.emailBreakdown.content.warningSigns.length > 0 ? (
                    <ul className="space-y-1 text-sm text-slate-600 dark:text-slate-300">
                      {result.emailBreakdown.content.warningSigns.map((warning) => (
                        <li key={warning}>- {warning}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-sm text-slate-500 dark:text-slate-400">
                      No phishing language patterns detected.
                    </p>
                  )}
                </RiskPanel>

                <RiskPanel icon={Link2} title="Link risk" analysis={result.emailBreakdown.links}>
                  {result.emailBreakdown.links.extracted.length > 0 ? (
                    <div className="space-y-2">
                      <div className="space-y-1">
                        {result.emailBreakdown.links.extracted.map((link) => (
                          <p
                            key={link}
                            className="truncate rounded-md bg-slate-100 px-2 py-1 text-xs text-slate-600 dark:bg-slate-950 dark:text-slate-300"
                          >
                            {link}
                          </p>
                        ))}
                      </div>
                      {result.emailBreakdown.links.warningSigns.length > 0 && (
                        <ul className="space-y-1 text-sm text-slate-600 dark:text-slate-300">
                          {result.emailBreakdown.links.warningSigns.map((warning) => (
                            <li key={warning}>- {warning}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ) : (
                    <p className="text-sm text-slate-500 dark:text-slate-400">
                      No links found in the email content.
                    </p>
                  )}
                </RiskPanel>
              </div>
            )}

            {result.blocked && (
              <div className="rounded-lg border border-rose-500/40 bg-rose-600 p-3 text-white">
                <div className="flex items-center gap-2 text-sm font-semibold">
                  <ShieldAlert size={17} />
                  Threat Blocked Automatically
                </div>
              </div>
            )}

            <div>
              <p className="mb-2 text-sm font-medium">Recommendation</p>
              <p className="text-sm text-slate-600 dark:text-slate-300">
                {result.recommendation}
              </p>
            </div>
          </div>
        ) : (
          <p className="mt-4 text-sm text-slate-500 dark:text-slate-400">
            Run an email analysis to see the safety score, indicators, and next action.
          </p>
        )}
      </Panel>
    </div>
  )
}
