import { useMemo, useState } from 'react'
import {
  ArrowLeft,
  Download,
  FileText,
  LockKeyhole,
  LogOut,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
} from 'lucide-react'
import { apiService } from '../services/api'

const formatDate = (value) => value
  ? new Intl.DateTimeFormat(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    }).format(new Date(value))
  : 'No activity'

const tabs = [
  { id: 'clients', label: 'Clients' },
  { id: 'reports', label: 'Reports' },
  { id: 'logs', label: 'Logs' },
]

export function Admin() {
  const [tokenInput, setTokenInput] = useState('')
  const [adminToken, setAdminToken] = useState('')
  const [tab, setTab] = useState('clients')
  const [overview, setOverview] = useState(null)
  const [clients, setClients] = useState([])
  const [logs, setLogs] = useState({ system: [], actions: [] })
  const [selected, setSelected] = useState(null)
  const [search, setSearch] = useState('')
  const [deleting, setDeleting] = useState(false)
  const [confirmId, setConfirmId] = useState('')
  const [verifiedRequest, setVerifiedRequest] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const visibleClients = useMemo(() =>
    clients.filter((client) => client.clientId.toLowerCase().includes(search.trim().toLowerCase())),
  [clients, search])

  const load = async (token) => {
    const [nextOverview, nextClients, nextLogs] = await Promise.all([
      apiService.getAdminOverview(token),
      apiService.getAdminClients(token),
      apiService.getAdminLogs(token),
    ])
    setOverview(nextOverview)
    setClients(nextClients)
    setLogs(nextLogs)
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

      <div role="tablist" aria-label="Admin views" className="flex gap-1 border-b border-slate-200 dark:border-slate-700">
        {tabs.map((item) => (
          <button key={item.id} type="button" role="tab" aria-selected={tab === item.id} onClick={() => { setTab(item.id); setSelected(null) }}
            className={`border-b-2 px-4 py-2.5 text-sm font-semibold ${tab === item.id ? 'border-emerald-500 text-emerald-700 dark:text-emerald-300' : 'border-transparent text-slate-500'}`}>
            {item.label}
          </button>
        ))}
      </div>

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
            <div className="relative max-w-sm">
              <Search size={17} className="absolute left-3 top-3 text-slate-400" />
              <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search client ID" aria-label="Search client ID"
                className="w-full rounded-md border border-slate-300 bg-white py-2.5 pl-9 pr-3 text-sm dark:border-slate-700 dark:bg-slate-900" />
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[650px] text-left text-sm">
                <thead className="border-b border-slate-300 text-slate-500 dark:border-slate-700"><tr><th className="py-2">Client ID</th><th>Scans</th><th>Last scan</th><th>Access</th></tr></thead>
                <tbody>{visibleClients.map((client) => (
                  <tr key={client.clientId} className="border-b border-slate-200 dark:border-slate-800">
                    <td className="py-2"><button type="button" onClick={() => selectClient(client.clientId)} className="font-mono text-emerald-700 hover:underline dark:text-emerald-300">{client.clientId}</button></td>
                    <td>{client.scanCount}</td><td>{formatDate(client.lastScanAt)}</td><td>{client.accessStatus === 'legacy' ? 'Legacy (unclaimed)' : 'Active'}</td>
                  </tr>
                ))}</tbody>
              </table>
              {visibleClients.length === 0 && <p className="py-4 text-sm text-slate-500">No clients found.</p>}
            </div>
          </section>
        )
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
