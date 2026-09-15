import { useMemo, useState } from 'react'
import {
  AlertTriangle,
  BellRing,
  CheckCircle2,
  FileWarning,
  Globe2,
  Info,
  ListChecks,
  MailPlus,
  MailWarning,
  Plus,
  Save,
  SearchCheck,
  ShieldCheck,
  Users,
  Trash2,
} from 'lucide-react'
import { Panel } from '../components/Panel'
import { useThreats } from '../hooks/useThreats'

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

const detectionRules = [
  {
    title: 'Suspicious domains and TLDs',
    icon: Globe2,
    status: 'Active',
    description:
      'Flags suspicious domain endings, risky domain names, piracy, gambling, and reward wording.',
    examples: ['.site, .zip, .top', 'torrent, crack, repack', 'bonus, billing, verify'],
  },
  {
    title: 'URL structure checks',
    icon: SearchCheck,
    status: 'Active',
    description:
      'Checks HTTPS, URL shorteners, punycode, brand lookalikes, mixed letters and numbers, and login paths.',
    examples: ['shorteners', 'fake brand domains', 'login or password paths'],
  },
  {
    title: 'Email and message analysis',
    icon: MailWarning,
    status: 'Active',
    description:
      'Scores sender, subject, body text, urgency language, credential requests, and links inside messages.',
    examples: ['urgent language', 'password request', 'embedded risky links'],
  },
  {
    title: 'File indicators',
    icon: FileWarning,
    status: 'Active',
    description:
      'Checks file names, extensions, scripts, suspicious text content, SHA-256 hash, and optional reputation lookups.',
    examples: ['invoice.pdf.exe', 'macro warning', 'VirusTotal hash lookup'],
  },
  {
    title: 'Threat intelligence',
    icon: ShieldCheck,
    status: 'When configured',
    description:
      'Uses external reputation providers when API keys are configured, while local rules keep working without them.',
    examples: ['URLhaus', 'PhishTank', 'VirusTotal, AbuseIPDB'],
  },
]

const scorePolicies = [
  {
    label: 'Safe',
    range: '80-100',
    action: 'Allowed',
    className: 'border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-300',
  },
  {
    label: 'Caution',
    range: '51-79',
    action: 'Review',
    className: 'border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-300',
  },
  {
    label: 'Dangerous',
    range: '0-50',
    action: 'Blocked',
    className: 'border-rose-200 bg-rose-50 text-rose-800 dark:border-rose-900/60 dark:bg-rose-950/30 dark:text-rose-300',
  },
]

function ToggleRow({ checked, description, label, onChange }) {
  return (
    <label className="flex items-start justify-between gap-4 rounded-lg border border-slate-200 p-3 dark:border-slate-800">
      <span>
        <span className="block text-sm font-semibold">{label}</span>
        <span className="mt-1 block text-sm text-slate-500 dark:text-slate-400">
          {description}
        </span>
      </span>
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="mt-1 h-5 w-5 accent-teal-600"
      />
    </label>
  )
}

export function Settings() {
  const {
    notificationSettings,
    saveNotificationSettings,
    sendHistoryDigest,
    setNotificationSettings,
  } = useThreats()
  const [draft, setDraft] = useState(notificationSettings)
  const [emailInput, setEmailInput] = useState('')
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const [digestSent, setDigestSent] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [isSendingDigest, setIsSendingDigest] = useState(false)

  const canSave = useMemo(
    () => draft.reportEmails.length > 0,
    [draft.reportEmails.length],
  )
  const mailStatus = notificationSettings.mailStatus
  const digestDisabledReason = useMemo(() => {
    if (!notificationSettings.mailConfigured) {
      if (mailStatus?.enabled === false) {
        return 'Email sender is disabled. Set SMTP_ENABLED=true or remove SMTP_ENABLED=false in Railway.'
      }
      const missing = mailStatus?.missing ?? []
      if (missing.length > 0) {
        return `Email sender is not configured. Missing Railway variables: ${missing.join(', ')}.`
      }
      return 'Email sender is not configured. Add SMTP variables in Railway first.'
    }
    if (!canSave) return 'Save at least one backtrack email first.'
    if (!draft.emailHistoryDigest) return 'Email history digest is turned off.'
    return ''
  }, [canSave, draft.emailHistoryDigest, mailStatus, notificationSettings.mailConfigured])

  const updateDraft = (changes) => {
    setDraft((current) => ({ ...current, ...changes }))
    setSaved(false)
    setDigestSent(false)
  }

  const addEmail = () => {
    const email = emailInput.trim().toLowerCase()
    if (!emailPattern.test(email)) {
      setError('Maglagay ng valid email address.')
      return
    }
    if (draft.reportEmails.includes(email)) {
      setError('Nasa listahan na ang email na ito.')
      return
    }

    updateDraft({ reportEmails: [...draft.reportEmails, email] })
    setEmailInput('')
    setError('')
  }

  const removeEmail = (email) => {
    updateDraft({ reportEmails: draft.reportEmails.filter((item) => item !== email) })
  }

  const saveSettings = async (event) => {
    event.preventDefault()
    if (!canSave) {
      setError('Maglagay ng kahit isang email.')
      return
    }

    setIsSaving(true)
    try {
      const settings = {
        ...draft,
        reportEmails: draft.reportEmails.map((email) => email.trim().toLowerCase()),
      }
      setNotificationSettings(settings)
      await saveNotificationSettings(settings)
      setError('')
      setSaved(true)
    } catch (saveError) {
      setError(saveError.message || 'Hindi na-save ang email notification settings.')
    } finally {
      setIsSaving(false)
    }
  }

  const emailDigest = async () => {
    setError('')
    setDigestSent(false)
    setIsSendingDigest(true)
    try {
      const settings = {
        ...draft,
        reportEmails: draft.reportEmails.map((email) => email.trim().toLowerCase()),
      }
      setNotificationSettings(settings)
      await sendHistoryDigest(settings)
      setDigestSent(true)
      setSaved(true)
    } catch (digestError) {
      setError(
        digestError.message ||
          'Hindi na-send ang history digest. Check SMTP settings and saved emails.',
      )
    } finally {
      setIsSendingDigest(false)
    }
  }

  return (
    <div className="space-y-5">
      <div>
        <p className="text-sm font-medium text-teal-700 dark:text-teal-300">Settings</p>
        <h1 className="text-2xl font-semibold">Detection rules and notifications</h1>
      </div>

      <Panel>
        <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <ListChecks size={19} className="text-teal-500" />
              <h2 className="text-lg font-semibold">Active detection policy</h2>
            </div>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600 dark:text-slate-300">
              These are the rule groups currently used by the scanner to score URLs, emails,
              messages, files, search results, and browser visits.
            </p>
          </div>
          <span className="inline-flex w-fit items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs font-semibold uppercase text-emerald-700 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-300">
            <CheckCircle2 size={15} />
            Policy active
          </span>
        </div>

        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
          {detectionRules.map((rule) => {
            const Icon = rule.icon
            return (
              <article
                key={rule.title}
                className="flex min-h-64 flex-col rounded-lg border border-slate-200 p-3 dark:border-slate-800"
              >
                <div className="flex items-start justify-between gap-3">
                  <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-teal-50 text-teal-700 dark:bg-teal-950/60 dark:text-teal-300">
                    <Icon size={19} />
                  </span>
                  <span className="rounded-full border border-slate-200 px-2 py-1 text-xs font-semibold text-slate-500 dark:border-slate-700 dark:text-slate-300">
                    {rule.status}
                  </span>
                </div>
                <h3 className="mt-3 text-sm font-semibold text-slate-950 dark:text-white">
                  {rule.title}
                </h3>
                <p className="mt-2 flex-1 text-sm leading-6 text-slate-600 dark:text-slate-300">
                  {rule.description}
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {rule.examples.map((example) => (
                    <span
                      key={example}
                      className="rounded-full bg-slate-100 px-2 py-1 text-xs font-semibold text-slate-600 dark:bg-slate-950 dark:text-slate-300"
                    >
                      {example}
                    </span>
                  ))}
                </div>
              </article>
            )
          })}
        </div>

        <div className="mt-5 grid gap-3 md:grid-cols-3">
          {scorePolicies.map((policy) => (
            <div key={policy.label} className={`rounded-lg border p-4 ${policy.className}`}>
              <div className="flex items-center justify-between gap-3">
                <p className="text-sm font-semibold">{policy.label}</p>
                <AlertTriangle size={17} className={policy.label === 'Dangerous' ? '' : 'hidden'} />
              </div>
              <p className="mt-2 text-2xl font-semibold">{policy.range}</p>
              <p className="mt-1 text-sm">System response: {policy.action}</p>
            </div>
          ))}
        </div>
      </Panel>

      <form className="grid gap-5 lg:grid-cols-[1.05fr_0.95fr]" onSubmit={saveSettings}>
        <div className="space-y-5">
          <Panel>
            <div className="flex items-center gap-2">
              <MailPlus size={19} className="text-teal-500" />
              <h2 className="text-lg font-semibold">Backtrack emails</h2>
            </div>

            <div className="mt-4 flex flex-col gap-2 sm:flex-row">
              <input
                className="min-w-0 flex-1 rounded-lg border border-slate-200 bg-white px-3 py-3 text-sm outline-none focus:border-teal-500 dark:border-slate-800 dark:bg-slate-950"
                type="email"
                value={emailInput}
                onChange={(event) => {
                  setEmailInput(event.target.value)
                  setError('')
                }}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') {
                    event.preventDefault()
                    addEmail()
                  }
                }}
                placeholder="TrackingThreats@example.com"
              />
              <button
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-teal-600 px-4 py-3 text-sm font-semibold text-white"
                type="button"
                onClick={addEmail}
              >
                <Plus size={17} />
                Add Email
              </button>
            </div>

            <div className="mt-4 space-y-2">
              {draft.reportEmails.length === 0 ? (
                <p className="rounded-lg border border-dashed border-slate-300 p-4 text-sm text-slate-500 dark:border-slate-700 dark:text-slate-400">
                  Walang email na naka-save.
                </p>
              ) : (
                draft.reportEmails.map((email) => (
                  <div
                    key={email}
                    className="flex items-center justify-between gap-3 rounded-lg border border-slate-200 p-3 dark:border-slate-800"
                  >
                    <span className="min-w-0 truncate text-sm font-medium">{email}</span>
                    <button
                      className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-slate-200 text-slate-500 hover:text-rose-600 dark:border-slate-800 dark:hover:text-rose-300"
                      type="button"
                      onClick={() => removeEmail(email)}
                      aria-label={`Remove ${email}`}
                      title="Remove email"
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                ))
              )}
            </div>
          </Panel>
        </div>

        <div className="space-y-5">
          <Panel>
            <div className="flex items-center gap-2">
              <BellRing size={19} className="text-teal-500" />
              <h2 className="text-lg font-semibold">Notification preferences</h2>
            </div>
            <div className="mt-4 space-y-3">
              <ToggleRow
                label="Email scanned records"
                description="Send scan summaries to saved emails."
                checked={draft.emailScanReports}
                onChange={(emailScanReports) => updateDraft({ emailScanReports })}
              />
              <ToggleRow
                label="Email history digest"
                description="Send saved history and reviewed threat records."
                checked={draft.emailHistoryDigest}
                onChange={(emailHistoryDigest) => updateDraft({ emailHistoryDigest })}
              />
            </div>
          </Panel>

          <Panel>
            {error && (
              <p className="mb-3 rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 text-sm font-medium text-rose-700 dark:text-rose-300">
                {error}
              </p>
            )}
            {saved && (
              <p className="mb-3 inline-flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm font-medium text-emerald-700 dark:text-emerald-300">
                <CheckCircle2 size={17} />
                Settings saved
              </p>
            )}
            {digestSent && (
              <p className="mb-3 inline-flex items-center gap-2 rounded-lg border border-sky-500/30 bg-sky-500/10 p-3 text-sm font-medium text-sky-700 dark:text-sky-300">
                <CheckCircle2 size={17} />
                History digest sent
              </p>
            )}
            <button
              className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-teal-600 px-4 py-3 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50"
              type="submit"
              disabled={!canSave || isSaving}
            >
              <Save size={17} />
              {isSaving ? 'Saving...' : 'Save Settings'}
            </button>
            <button
              className="mt-3 inline-flex w-full items-center justify-center gap-2 rounded-lg border border-slate-200 px-4 py-3 text-sm font-semibold text-slate-700 disabled:cursor-not-allowed disabled:opacity-50 dark:border-slate-800 dark:text-slate-200"
              type="button"
              onClick={emailDigest}
              disabled={
                !notificationSettings.mailConfigured ||
                !draft.emailHistoryDigest ||
                !canSave ||
                isSendingDigest
              }
            >
              <BellRing size={17} />
              {isSendingDigest ? 'Sending digest...' : 'Send History Digest'}
            </button>
            {digestDisabledReason && (
              <p className="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm font-medium text-amber-700 dark:text-amber-300">
                {digestDisabledReason}
              </p>
            )}
          </Panel>
        </div>
      </form>

      <Panel>
        <div className="grid gap-5 lg:grid-cols-[1.1fr_0.9fr]">
          <div>
            <div className="flex items-center gap-2">
              <Info size={19} className="text-teal-500" />
              <h2 className="text-lg font-semibold">About Tracking Threats</h2>
            </div>
            <p className="mt-3 text-sm leading-6 text-slate-600 dark:text-slate-300">
              Tracking Threats is a hosted phishing detection and browser monitoring system that helps users scan
              suspicious URLs, emails, and messages. It records scan history, flags dangerous
              content, shows alerts, and gives recommendations so users can review threats before
              trusting unknown links or messages.
            </p>
          </div>

          <div>
            <div className="flex items-center gap-2">
              <Users size={19} className="text-teal-500" />
              <h2 className="text-lg font-semibold">Contact the staff of Tracking Threats</h2>
            </div>
            <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-1">
              {['Alemari Acuesta', 'Bryan Duran', 'Niccolo Valero', 'James Torralba'].map(
                (name) => (
                  <div
                    key={name}
                    className="rounded-lg border border-slate-200 px-3 py-2 text-sm font-medium dark:border-slate-800"
                  >
                    {name}
                  </div>
                ),
              )}
            </div>
          </div>
        </div>
      </Panel>
    </div>
  )
}
