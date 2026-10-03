import { useEffect, useMemo, useState } from 'react'
import {
  ArrowLeft,
  Download,
  FileText,
  Globe2,
  LockKeyhole,
  LogOut,
  Megaphone,
  Minus,
  Monitor,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
} from 'lucide-react'
import { apiService } from '../services/api'
import { EvaluationPanel } from '../components/EvaluationPanel'
import {
  adminClientFilters,
  filterAdminClients,
  formatRelativeTime,
  getClientPresence,
  getLatestClientActivity,
  isLinkedActiveClient,
} from '../utils/adminClients'

const formatDate = (value) => value
  ? new Intl.DateTimeFormat(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    }).format(new Date(value))
  : 'No activity'

const tabs = [
  { id: 'clients', label: 'Clients' },
  { id: 'announcements', label: 'Announcements' },
  { id: 'reports', label: 'Reports' },
  { id: 'logs', label: 'Logs' },
  { id: 'evaluation', label: 'Evaluation' },
]

const emptyAnnouncementForm = {
  type: 'update',
  title: '',
  message: '',
  priority: 'important',
  targetVersion: '',
  expiresAt: '',
  isActive: true,
}

const usageMetrics = [
  ['extensionDownloads', 'Extension download requests'],

  ['registeredDevices', 'Registered devices'],
  ['activeDevices24h', 'Active devices · 24 hours'],
  ['activeDevices7d', 'Active devices · 7 days'],

  ['registeredExtensions', 'Extension installations'],
  ['activeExtensions24h', 'Active extensions · 24 hours'],
  ['activeExtensions7d', 'Active extensions · 7 days'],
]

export function Admin() {
  const [tokenInput, setTokenInput] = useState('')
  const [adminToken, setAdminToken] = useState('')
  const [tab, setTab] = useState('clients')
  const [overview, setOverview] = useState(null)
  const [clients, setClients] = useState([])
  const [logs, setLogs] = useState({ system: [], actions: [] })
  const [announcements, setAnnouncements] = useState([])
  const [announcementForm, setAnnouncementForm] = useState(emptyAnnouncementForm)
  const [selected, setSelected] = useState(null)
  const [search, setSearch] = useState('')
  const [clientFilter, setClientFilter] = useState('linked')
  const [relativeTimeReference, setRelativeTimeReference] = useState(() => Date.now())
  const [deleting, setDeleting] = useState(false)
  const [confirmId, setConfirmId] = useState('')
  const [verifiedRequest, setVerifiedRequest] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const clientCounts = useMemo(() => ({
    all: clients.length,
    linked: clients.filter(isLinkedActiveClient).length,
    legacy: clients.filter((client) => !isLinkedActiveClient(client)).length,
  }), [clients])

  const visibleClients = useMemo(() => {
    const query = search.trim().toLowerCase()
    return filterAdminClients(clients, clientFilter)
      .filter((client) => client.clientId.toLowerCase().includes(query))
  }, [clientFilter, clients, search])

  useEffect(() => {
    if (!adminToken) return undefined
    const timer = window.setInterval(() => setRelativeTimeReference(Date.now()), 30 * 1000)
    return () => window.clearInterval(timer)
  }, [adminToken])

  const load = async (token) => {
    const [nextOverview, nextClients, nextLogs, nextAnnouncements] = await Promise.all([
      apiService.getAdminOverview(token),
      apiService.getAdminClients(token),
      apiService.getAdminLogs(token),
      apiService.getAdminAnnouncements(token),
    ])
    setOverview(nextOverview)
    setClients(nextClients)
    setLogs(nextLogs)
    setAnnouncements(nextAnnouncements)
    setRelativeTimeReference(Date.now())
  }

  const signIn = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await load(tokenInput.trim())
      setAdminToken(tokenInput.trim())
      setTokenInput('')
    } catch (loginError) {
      setError(loginError.message || 'Admin access failed')
    } finally {
      setBusy(false)
    }
  }

  const refresh = async () => {
    setBusy(true)
    setError('')
    try {
      await load(adminToken)
      if (selected) setSelected(await apiService.getAdminClient(adminToken, selected.clientId))
    } catch (refreshError) {
      setError(refreshError.message || 'Could not refresh admin data')
    } finally {
      setBusy(false)
    }
  }

  const selectClient = async (clientId) => {
    setError('')
    setBusy(true)
    try {
      setSelected(await apiService.getAdminClient(adminToken, clientId))
      setDeleting(false)
    } catch (selectError) {
      setError(selectError.message || 'Could not load client')
    } finally {
      setBusy(false)
    }
  }

  const createAnnouncement = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const created = await apiService.createAdminAnnouncement(adminToken, {
        ...announcementForm,
        targetVersion: announcementForm.type === 'update' ? announcementForm.targetVersion.trim() : '',
        expiresAt: announcementForm.expiresAt
          ? new Date(announcementForm.expiresAt).toISOString()
          : null,
      })
      setAnnouncements((current) => [created, ...current])
      setAnnouncementForm(emptyAnnouncementForm)
      setNotice(created.isActive ? 'Announcement published.' : 'Announcement saved as a draft.')
    } catch (announcementError) {
      setError(announcementError.message || 'Could not save announcement')
    } finally {
      setBusy(false)
    }
  }

  const toggleAnnouncement = async (announcement) => {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const updated = await apiService.updateAdminAnnouncement(
        adminToken,
        announcement.id,
        { isActive: !announcement.isActive },
      )
      setAnnouncements((current) => current.map((item) => item.id === updated.id ? updated : item))
      setNotice(updated.isActive ? 'Announcement published.' : 'Announcement unpublished.')
    } catch (announcementError) {
      setError(announcementError.message || 'Could not update announcement')
    } finally {
      setBusy(false)
    }
  }

  const deleteData = async (event) => {
    event.preventDefault()
    if (!selected || confirmId !== selected.clientId || !verifiedRequest) return
    setBusy(true)
    setError('')
    try {
      const result = await apiService.deleteAdminClientData(adminToken, selected.clientId)
      setNotice(`Deleted ${result.deletedScans} scans for the confirmed client.`)
      setSelected(null)
      setDeleting(false)
      setConfirmId('')
      setVerifiedRequest(false)
      await load(adminToken)
    } catch (deleteError) {
      setError(deleteError.message || 'Client deletion failed')
    } finally {
      setBusy(false)
    }
  }

  const signOut = () => {
    setAdminToken('')
    setTokenInput('')
    setSelected(null)
    setOverview(null)
    setClients([])
    setAnnouncements([])
    setLogs({ system: [], actions: [] })
    setError('')
    setNotice('')
  }

  const downloadReport = () => {
    if (!overview) return
    const rows = [
      ['Category', 'Value', 'Count'],
      ['Summary', 'Registered clients', overview.clients],
      ['Summary', 'Stored scans', overview.scans],
      ['Summary', 'Scans in 24 hours', overview.scansLast24Hours],
      ...usageMetrics.map(([key, label]) => ['Usage', label, overview.usage?.[key] ?? 0]),
      ...overview.byType.map((row) => ['Scan type', row.type, row.count]),
      ...overview.byStatus.map((row) => ['Outcome', row.status, row.count]),
    ]
    const csv = rows.map((row) => row.map((value) =>
      `"${String(value ?? '').replaceAll('"', '""')}"`).join(',')).join('\r\n')
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `tracking-threats-report-${new Date().toISOString().slice(0, 10)}.csv`
    link.click()
    URL.revokeObjectURL(url)
  }

  if (!adminToken) {
    return (
      <div className="mx-auto max-w-md pt-8">
        <div className="mb-6 flex items-center gap-3">
          <ShieldCheck className="text-emerald-600 dark:text-emerald-400" size={25} />
          <div>
            <p className="text-sm text-slate-500 dark:text-slate-400">Restricted access</p>
            <h1 className="text-2xl font-semibold">Admin</h1>
          </div>
        </div>
        <form onSubmit={signIn} className="rounded-lg border border-emerald-100 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
          <label htmlFor="admin-token" className="mb-2 block text-sm font-semibold">Admin Only Access Key</label>
          <div className="relative">
            <LockKeyhole size={18} className="absolute left-3 top-3 text-slate-400" />
            <input
              id="admin-token"
              type="password"
              autoComplete="off"
              value={tokenInput}
              onChange={(event) => setTokenInput(event.target.value)}
              className="w-full rounded-md border border-slate-300 bg-white py-2.5 pl-10 pr-3 text-sm dark:border-slate-600 dark:bg-slate-900"
              required
            />
          </div>
          {error && <p role="alert" className="mt-3 text-sm text-rose-600 dark:text-rose-300">{error}</p>}
          <button type="submit" disabled={busy} className="mt-4 w-full rounded-md bg-emerald-600 px-4 py-2.5 font-semibold text-white disabled:opacity-60">
            {busy ? 'Checking...' : 'Sign in'}
          </button>
        </form>
      </div>
    )
  }

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-sm text-emerald-700 dark:text-emerald-300">Administration</p>
          <h1 className="text-2xl font-semibold">Client records and operations</h1>
        </div>
        <div className="flex gap-2">
          <button type="button" title="Refresh" aria-label="Refresh" disabled={busy} onClick={refresh} className="grid h-10 w-10 place-items-center rounded-md border border-slate-300 dark:border-slate-700">
            <RefreshCw size={18} />
          </button>
          <button type="button" onClick={signOut} className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm dark:border-slate-700">
            <LogOut size={17} /> Sign out
          </button>
        </div>
      </header>

      {error && <p role="alert" className="rounded-md border border-rose-300 bg-rose-50 px-3 py-2 text-sm text-rose-800 dark:border-rose-900 dark:bg-rose-950/30 dark:text-rose-300">{error}</p>}
      {notice && <p role="status" className="rounded-md border border-emerald-300 bg-emerald-50 px-3 py-2 text-sm text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-300">{notice}</p>}

      <section aria-label="Extension and system usage" className="rounded-lg border border-emerald-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-900">
        <h2 className="text-lg font-semibold">Extension and system usage</h2>
        <div className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {usageMetrics.map(([key, label]) => (
            <div key={key}>
              <p className="text-sm text-slate-500 dark:text-slate-400">{label}</p>
              <p className="mt-1 text-2xl font-semibold">{overview?.usage?.[key] ?? 0}</p>
            </div>
          ))}
        </div>
        <p className="mt-4 text-xs leading-5 text-slate-500 dark:text-slate-400">
          Tracking since {formatDate(overview?.usage?.trackingStartedAt)}. Downloads count ZIP requests, including repeats, not confirmed installs.
          Registered extensions are current client IDs that have reported from extension v1.0.26 or newer, not verified installed copies.
          Active means a recent server contact; it does not mean someone is online right now. System clients include website and extension activity.
          One person can have multiple clients. Older downloads cannot be recovered; existing extensions must be updated to report usage. Deleted client records leave these client counts. Use Refresh to update.
        </p>
      </section>

      <div role="tablist" aria-label="Admin views" className="flex flex-wrap gap-1 border-b border-slate-200 dark:border-slate-700">
        {tabs.map((item) => (
          <button key={item.id} type="button" role="tab" aria-selected={tab === item.id} onClick={() => { setTab(item.id); setSelected(null) }}
            className={`border-b-2 px-4 py-2.5 text-sm font-semibold ${tab === item.id ? 'border-emerald-500 text-emerald-700 dark:text-emerald-300' : 'border-transparent text-slate-500'}`}>
            {item.label}
          </button>
        ))}
      </div>

      {tab === 'evaluation' && <EvaluationPanel token={adminToken} />}

      {tab === 'clients' && (
        selected ? (
          <section className="space-y-5">
            <button type="button" onClick={() => { setSelected(null); setDeleting(false) }} className="inline-flex items-center gap-2 text-sm text-emerald-700 dark:text-emerald-300">
              <ArrowLeft size={17} /> Clients
            </button>
            <div className="border-b border-slate-200 pb-4 dark:border-slate-700">
              <h2 className="break-all text-lg font-semibold">{selected.clientId}</h2>
              <p className="text-sm text-slate-500 dark:text-slate-400">Redacted scan outcomes only. Raw email and file content is not shown.</p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[550px] text-left text-sm">
                <thead className="border-b border-slate-300 text-slate-500 dark:border-slate-700"><tr><th className="py-2">Date</th><th>Type</th><th>Status</th><th>Score</th></tr></thead>
                <tbody>{selected.recent.map((scan) => (
                  <tr key={scan.id} className="border-b border-slate-200 dark:border-slate-800"><td className="py-2">{formatDate(scan.created_at)}</td><td>{scan.type}</td><td>{scan.status}</td><td>{scan.score}/100</td></tr>
                ))}</tbody>
              </table>
              {selected.recent.length === 0 && <p className="py-4 text-sm text-slate-500">No scan records.</p>}
            </div>
            <div className="border-t border-rose-200 pt-5 dark:border-rose-900/50">
              {!deleting ? (
                <button type="button" onClick={() => setDeleting(true)} className="inline-flex items-center gap-2 rounded-md border border-rose-400 px-3 py-2 text-sm font-semibold text-rose-700 dark:text-rose-300">
                  <Trash2 size={17} /> Delete client data
                </button>
              ) : (
                <form onSubmit={deleteData} className="max-w-lg space-y-3">
                  <h3 className="font-semibold text-rose-700 dark:text-rose-300">Permanent deletion</h3>
                  <p className="text-sm text-slate-600 dark:text-slate-300">Verify the client request first. This removes the client credential, history, evidence, related logs, and report settings.</p>
                  <label className="flex items-start gap-2 text-sm">
                    <input type="checkbox" checked={verifiedRequest} onChange={(event) => setVerifiedRequest(event.target.checked)} className="mt-1 accent-rose-600" />
                    I verified this client's deletion request.
                  </label>
                  <label className="block text-sm font-semibold" htmlFor="confirm-client-id">Type the exact client ID to confirm</label>
                  <input id="confirm-client-id" value={confirmId} onChange={(event) => setConfirmId(event.target.value)} autoComplete="off"
                    className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-sm dark:border-slate-700 dark:bg-slate-900" />
                  <div className="flex gap-2">
                    <button type="submit" disabled={busy || !verifiedRequest || confirmId !== selected.clientId}
                      className="rounded-md bg-rose-600 px-3 py-2 text-sm font-semibold text-white disabled:opacity-50">Delete permanently</button>
                    <button type="button" onClick={() => { setDeleting(false); setConfirmId(''); setVerifiedRequest(false) }} className="rounded-md border border-slate-300 px-3 py-2 text-sm dark:border-slate-700">Cancel</button>
                  </div>
                </form>
              )}
            </div>
          </section>
        ) : (
          <section className="space-y-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <div className="relative w-full max-w-sm">
                <Search size={17} className="absolute left-3 top-3 text-slate-400" />
                <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search client ID" aria-label="Search client ID"
                  className="w-full rounded-md border border-slate-300 bg-white py-2.5 pl-9 pr-3 text-sm dark:border-slate-700 dark:bg-slate-900" />
              </div>
              <div role="group" aria-label="Filter clients" className="flex max-w-full gap-1 overflow-x-auto rounded-lg bg-slate-100 p-1 dark:bg-slate-950">
                {adminClientFilters.map((filter) => (
                  <button
                    key={filter.id}
                    type="button"
                    aria-pressed={clientFilter === filter.id}
                    onClick={() => setClientFilter(filter.id)}
                    className={`whitespace-nowrap rounded-md px-3 py-2 text-sm font-semibold ${
                      clientFilter === filter.id
                        ? 'bg-white text-slate-950 shadow-sm dark:bg-slate-800 dark:text-white'
                        : 'text-slate-500 dark:text-slate-400'
                    }`}
                  >
                    {filter.label} ({clientCounts[filter.id]})
                  </button>
                ))}
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1100px] table-fixed text-left text-sm">
                <thead className="border-b border-slate-300 text-slate-500 dark:border-slate-700">
                   <tr>
                      <th className="w-[220px] py-2 pr-4">Client ID</th>
                      <th className="w-[130px] pr-4">Device</th>
                      <th className="w-[95px] pr-4">Browser</th>
                      <th className="w-[60px] pr-4">Scans</th>
                      <th className="w-[160px] pr-4">Last scan</th>
                      <th className="w-[180px] pr-4">Last active</th>
                      <th className="w-[90px] pr-4">Extension</th>
                      <th className="w-[180px]">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleClients.map((client) => {
                    const linked = isLinkedActiveClient(client)
                    const presence = getClientPresence(client, relativeTimeReference)
                    const lastActiveAt = getLatestClientActivity(client)
                    return (
                      <tr key={client.clientId} className="border-b border-slate-200 dark:border-slate-800">
                        <td className="py-2 pr-4">
                          <button
                            type="button"
                            onClick={() => selectClient(client.clientId)}
                            title={client.clientId}
                            className="block max-w-[200px] truncate font-mono text-emerald-700 hover:underline dark:text-emerald-300"
                          >
                            {client.clientId}
                          </button>
                        </td>

                        <td className="pr-4">
                          <span className="inline-flex max-w-full items-center gap-2">
                            {client.deviceName ? <Monitor size={16} className="text-slate-400" /> : <Minus size={16} className="text-slate-400" />}
                            <span className="truncate" title={client.deviceName || 'N/A'}>{client.deviceName || 'N/A'}</span>
                          </span>
                        </td>

                        <td className="pr-4">
                          <span className="inline-flex items-center gap-2">
                            {client.browserName ? <Globe2 size={16} className="text-slate-400" /> : <Minus size={16} className="text-slate-400" />}
                            {client.browserName || 'N/A'}
                          </span>
                        </td>

                        <td className="pr-4">{client.scanCount}</td>

                        <td className="pr-4">{formatDate(client.lastScanAt)}</td>

                        <td className="pr-4">
                          <span>{formatDate(lastActiveAt)}</span>
                          {lastActiveAt && (
                            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                              {formatRelativeTime(lastActiveAt, relativeTimeReference)}
                            </p>
                          )}
                        </td>

                        <td className="pr-4">
                          {client.extensionVersion ? (
                            <span>v{client.extensionVersion}</span>
                          ) : (
                            'N/A'
                          )}
                        </td>

                        <td>
                          <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${
                            linked
                              ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300'
                              : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'
                          }`}>
                            {linked ? 'Linked' : 'Legacy / Unlinked'}
                          </span>
                          <p className="mt-1.5 flex items-center gap-1.5 font-medium">
                            <span aria-hidden="true" className={`h-2 w-2 rounded-full ${presence.isOnline ? 'bg-emerald-500' : 'bg-slate-400'}`} />
                            {presence.isOnline ? 'Online' : 'Offline'}
                          </p>
                          <p className="mt-0.5 whitespace-nowrap text-xs text-slate-500 dark:text-slate-400">
                            Last heartbeat: {presence.relative}
                          </p>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
              {visibleClients.length === 0 && (
                <p className="py-4 text-sm text-slate-500">
                  No clients found in the {adminClientFilters.find((filter) => filter.id === clientFilter)?.label ?? 'selected'} view.
                </p>
              )}
            </div>
          </section>
        )
      )}

      {tab === 'announcements' && (
        <section className="grid gap-6 xl:grid-cols-[minmax(0,420px)_1fr]">
          <form onSubmit={createAnnouncement} className="space-y-4 rounded-lg border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-900">
            <div>
              <p className="text-sm text-emerald-700 dark:text-emerald-300">Staff publishing</p>
              <h2 className="mt-1 flex items-center gap-2 text-lg font-semibold">
                <Megaphone size={19} /> New announcement
              </h2>
              <p className="mt-1 text-xs leading-5 text-slate-500 dark:text-slate-400">
                Published items appear in the extension announcement panel. Update links always use the official extension download endpoint.
              </p>
            </div>

            <label className="block text-sm font-semibold">
              Type
              <select
                value={announcementForm.type}
                onChange={(event) => setAnnouncementForm((current) => ({ ...current, type: event.target.value }))}
                className="mt-1.5 w-full rounded-md border border-slate-300 bg-white px-3 py-2.5 font-normal dark:border-slate-700 dark:bg-slate-950"
              >
                <option value="update">Extension update</option>
                <option value="security">Security advisory</option>
                <option value="maintenance">Maintenance</option>
                <option value="general">General announcement</option>
              </select>
            </label>

            <label className="block text-sm font-semibold">
              Title
              <input
                value={announcementForm.title}
                onChange={(event) => setAnnouncementForm((current) => ({ ...current, title: event.target.value }))}
                maxLength={120}
                required
                className="mt-1.5 w-full rounded-md border border-slate-300 bg-white px-3 py-2.5 font-normal dark:border-slate-700 dark:bg-slate-950"
              />
            </label>

            <label className="block text-sm font-semibold">
              Message
              <textarea
                value={announcementForm.message}
                onChange={(event) => setAnnouncementForm((current) => ({ ...current, message: event.target.value }))}
                maxLength={1000}
                rows={5}
                required
                className="mt-1.5 w-full resize-y rounded-md border border-slate-300 bg-white px-3 py-2.5 font-normal dark:border-slate-700 dark:bg-slate-950"
              />
            </label>

            {announcementForm.type === 'update' && (
              <label className="block text-sm font-semibold">
                New extension version
                <input
                  value={announcementForm.targetVersion}
                  onChange={(event) => setAnnouncementForm((current) => ({ ...current, targetVersion: event.target.value }))}
                  placeholder="Example: 1.0.36"
                  pattern="\d{1,5}\.\d{1,5}\.\d{1,5}(\.\d{1,5})?"
                  required
                  className="mt-1.5 w-full rounded-md border border-slate-300 bg-white px-3 py-2.5 font-normal dark:border-slate-700 dark:bg-slate-950"
                />
              </label>
            )}

            <div className="grid gap-4 sm:grid-cols-2">
              <label className="block text-sm font-semibold">
                Priority
                <select
                  value={announcementForm.priority}
                  onChange={(event) => setAnnouncementForm((current) => ({ ...current, priority: event.target.value }))}
                  className="mt-1.5 w-full rounded-md border border-slate-300 bg-white px-3 py-2.5 font-normal dark:border-slate-700 dark:bg-slate-950"
                >
                  <option value="normal">Normal</option>
                  <option value="important">Important</option>
                  <option value="critical">Critical</option>
                </select>
              </label>
              <label className="block text-sm font-semibold">
                Expires (optional)
                <input
                  type="datetime-local"
                  value={announcementForm.expiresAt}
                  onChange={(event) => setAnnouncementForm((current) => ({ ...current, expiresAt: event.target.value }))}
                  className="mt-1.5 w-full rounded-md border border-slate-300 bg-white px-3 py-2.5 font-normal dark:border-slate-700 dark:bg-slate-950"
                />
              </label>
            </div>

            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                checked={announcementForm.isActive}
                onChange={(event) => setAnnouncementForm((current) => ({ ...current, isActive: event.target.checked }))}
                className="mt-1 accent-emerald-600"
              />
              Publish immediately. Clear this to save a draft.
            </label>

            <button type="submit" disabled={busy} className="w-full rounded-md bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white disabled:opacity-60">
              {busy ? 'Saving...' : announcementForm.isActive ? 'Publish announcement' : 'Save draft'}
            </button>
          </form>

          <div className="space-y-3">
            <div>
              <h2 className="text-lg font-semibold">Published and draft announcements</h2>
              <p className="text-sm text-slate-500 dark:text-slate-400">Newest items appear first.</p>
            </div>
            {announcements.map((announcement) => (
              <article key={announcement.id} className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-900">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2 text-xs font-semibold uppercase tracking-wide">
                      <span className="rounded-full bg-slate-100 px-2 py-1 text-slate-600 dark:bg-slate-800 dark:text-slate-300">{announcement.type}</span>
                      <span className={announcement.priority === 'critical' ? 'text-rose-600 dark:text-rose-300' : announcement.priority === 'important' ? 'text-amber-700 dark:text-amber-300' : 'text-slate-500'}>{announcement.priority}</span>
                      <span className={announcement.isActive ? 'text-emerald-700 dark:text-emerald-300' : 'text-slate-500'}>{announcement.isActive ? 'Published' : 'Draft'}</span>
                    </div>
                    <h3 className="mt-2 font-semibold">{announcement.title}</h3>
                    {announcement.targetVersion && <p className="mt-1 text-sm font-medium text-emerald-700 dark:text-emerald-300">Extension v{announcement.targetVersion}</p>}
                  </div>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => toggleAnnouncement(announcement)}
                    className="rounded-md border border-slate-300 px-3 py-2 text-xs font-semibold dark:border-slate-700"
                  >
                    {announcement.isActive ? 'Unpublish' : 'Publish'}
                  </button>
                </div>
                <p className="mt-3 whitespace-pre-wrap text-sm leading-6 text-slate-600 dark:text-slate-300">{announcement.message}</p>
                <p className="mt-3 text-xs text-slate-500">
                  {announcement.publishedAt ? `Published ${formatDate(announcement.publishedAt)}` : 'Not published'}
                  {announcement.expiresAt ? ` · Expires ${formatDate(announcement.expiresAt)}` : ''}
                </p>
              </article>
            ))}
            {announcements.length === 0 && (
              <p className="rounded-lg border border-dashed border-slate-300 p-5 text-sm text-slate-500 dark:border-slate-700">No announcements yet.</p>
            )}
          </div>
        </section>
      )}

      {tab === 'reports' && (
        <section className="space-y-5">
          <div className="flex justify-end">
            <button type="button" onClick={downloadReport} className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-semibold dark:border-slate-700">
              <Download size={17} /> Download CSV
            </button>
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            {[['Registered clients', overview?.clients], ['Stored scans', overview?.scans], ['Scans in 24 hours', overview?.scansLast24Hours]].map(([label, value]) => (
              <div key={label} className="border-b border-slate-200 pb-4 dark:border-slate-700">
                <p className="text-sm text-slate-500 dark:text-slate-400">{label}</p>
                <p className="mt-1 text-2xl font-semibold">{value ?? 0}</p>
              </div>
            ))}
          </div>
          <div className="grid gap-6 md:grid-cols-2">
            {[['Scan types', overview?.byType ?? [], 'type'], ['Outcomes', overview?.byStatus ?? [], 'status']].map(([title, rows, key]) => (
              <div key={title}>
                <h2 className="mb-3 flex items-center gap-2 font-semibold"><FileText size={18} /> {title}</h2>
                {rows.map((row) => (
                  <div key={row[key]} className="flex justify-between border-b border-slate-200 py-2 text-sm dark:border-slate-800"><span>{row[key]}</span><strong>{row.count}</strong></div>
                ))}
                {rows.length === 0 && <p className="text-sm text-slate-500">No records.</p>}
              </div>
            ))}
          </div>
        </section>
      )}

      {tab === 'logs' && (
        <section className="grid gap-6 lg:grid-cols-2">
          <div>
            <h2 className="mb-3 font-semibold">System events</h2>
            {logs.system.map((entry) => (
              <div key={entry.id} className="border-b border-slate-200 py-2 text-sm dark:border-slate-800">
                <span className="font-medium">{entry.event}</span> <span className="text-slate-500">({entry.level})</span>
                <p className="text-xs text-slate-500">{formatDate(entry.created_at)}</p>
              </div>
            ))}
            {logs.system.length === 0 && <p className="text-sm text-slate-500">No system events.</p>}
          </div>
          <div>
            <h2 className="mb-3 font-semibold">Admin actions</h2>
            {logs.actions.map((entry) => (
              <div key={entry.id} className="border-b border-slate-200 py-2 text-sm dark:border-slate-800">
                <span className="font-medium">{entry.action}</span> <span className="text-slate-500">({entry.deleted_scans} scans)</span>
                <p className="font-mono text-xs text-slate-500">{entry.client_ref} | {formatDate(entry.created_at)}</p>
              </div>
            ))}
            {logs.actions.length === 0 && <p className="text-sm text-slate-500">No admin actions.</p>}
          </div>
        </section>
      )}
    </div>
  )
}
