import { useMemo, useState } from 'react'
import {
  BellRing,
  CheckCircle2,
  Info,
  MailPlus,
  Plus,
  Save,
  Users,
  Trash2,
} from 'lucide-react'
import { Panel } from '../components/Panel'
import { useThreats } from '../hooks/useThreats'

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

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
  const { notificationSettings, setNotificationSettings } = useThreats()
  const [draft, setDraft] = useState(notificationSettings)
  const [emailInput, setEmailInput] = useState('')
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)

  const canSave = useMemo(
    () => draft.reportEmails.length > 0,
    [draft.reportEmails.length],
  )

  const updateDraft = (changes) => {
    setDraft((current) => ({ ...current, ...changes }))
    setSaved(false)
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

  const saveSettings = (event) => {
    event.preventDefault()
    if (!canSave) {
      setError('Maglagay ng kahit isang email.')
      return
    }

    setNotificationSettings({
      ...draft,
      reportEmails: draft.reportEmails.map((email) => email.trim().toLowerCase()),
    })
    setError('')
    setSaved(true)
  }

  return (
    <div className="space-y-5">
      <div>
        <p className="text-sm font-medium text-teal-700 dark:text-teal-300">Settings</p>
        <h1 className="text-2xl font-semibold">Contact and notification setup</h1>
      </div>

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
                placeholder="security@example.com"
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
            <button
              className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-teal-600 px-4 py-3 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50"
              type="submit"
              disabled={!canSave}
            >
              <Save size={17} />
              Save Settings
            </button>
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
              Tracking Threats is a local phishing detection system that helps users scan
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
