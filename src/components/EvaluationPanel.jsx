import { useEffect, useState } from 'react'
import { apiService } from '../services/api'

const percent = (value) => value == null ? 'N/A' : `${(value * 100).toFixed(2)}%`
const field = 'rounded border border-slate-300 bg-white p-2 text-slate-900 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100'

export function EvaluationPanel({ token }) {
  const [catalog, setCatalog] = useState({ datasets: [], history: [] })
  const [dataset, setDataset] = useState('synthetic')
  const [mode, setMode] = useState('production')
  const [limit, setLimit] = useState(20)
  const [run, setRun] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [policy, setPolicy] = useState('warning')

  useEffect(() => {
    let cancelled = false
    const refresh = async () => {
      try {
        const value = await apiService.getEvaluations(token)
        if (!cancelled) setCatalog(value)
        if (run?.status === 'running') {
          const next = await apiService.getEvaluation(token, run.id)
          if (!cancelled) setRun(next)
        }
      } catch (failure) { if (!cancelled) setError(failure.message) }
    }
    void refresh()
    const timer = setInterval(refresh, 4000)
    return () => { cancelled = true; clearInterval(timer) }
  }, [token, run?.id, run?.status])

  const start = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError('')
    try { setRun(await apiService.runEvaluation(token, { dataset, mode, limit: Number(limit) })) }
    catch (failure) { setError(failure.message) }
    finally { setBusy(false) }
  }
  const view = async (id) => {
    setError('')
    try { setRun(await apiService.getEvaluation(token, id)) }
    catch (failure) { setError(failure.message) }
  }
  const report = run?.report
  const metrics = report?.metrics.overall[policy]
  const exportReport = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `evaluation-${run.id}.json`
    link.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  return (
    <section className="space-y-5 py-5">
      <h2 className="text-xl font-semibold">Detection evaluation</h2>
      <p className="text-sm">{catalog.policy}</p>
      <p className="text-sm text-slate-500">Synthetic regression and externally labeled PhiUSIIL samples are reported separately. Automated test pass counts are not detection accuracy. The existing lexical model uses PhiUSIIL tuning data; only held-out rows are eligible here.</p>
      <form onSubmit={start} className="flex flex-wrap items-end gap-3">
        <label htmlFor="evaluation-dataset" className="grid gap-1 text-sm">Dataset
          <select id="evaluation-dataset" aria-label="Dataset" className={field} value={dataset} onChange={(event) => setDataset(event.target.value)}>
            {catalog.datasets.map((item) => <option key={item.id} value={item.id} disabled={!item.available}>{item.name}{item.available ? '' : ' (not configured)'}</option>)}
          </select>
        </label>
        <label htmlFor="evaluation-detector" className="grid gap-1 text-sm">Detector
          <select id="evaluation-detector" aria-label="Detector" className={field} value={mode} onChange={(event) => { setMode(event.target.value); setLimit(20) }}>
            <option value="production">Production pipeline (configured providers)</option>
            <option value="local">Local detector only (no online checks)</option>
          </select>
        </label>
        <label htmlFor="evaluation-limit" className="grid gap-1 text-sm">Maximum samples
          <input id="evaluation-limit" aria-label="Maximum samples" className={`${field} w-28`} type="number" min="2" max={mode === 'production' ? 100 : 5000} value={limit} onChange={(event) => setLimit(event.target.value)} required />
        </label>
        <button className="rounded bg-emerald-700 px-4 py-2 text-white disabled:opacity-50" disabled={busy || run?.status === 'running' || catalog.history.some((item) => item.status === 'running')}>Run evaluation</button>
      </form>
      <p className="text-xs text-slate-500">Production runs contact configured reputation services and inspect reachable HTTPS pages. Missing providers remain unavailable. Local runs omit these checks. PhiUSIIL is available when its existing JSONL dataset is installed on the server.</p>
      {error && <p role="alert" className="text-rose-600">{error}</p>}
      {run && <p role="status">Run: {run.status} · {run.processed ?? 0}/{run.total} processed {run.error && `· ${run.error}`}</p>}
      {report && <div className="space-y-4">
        <p>{report.sample.evaluated} evaluated: {report.sample.phishing} phishing, {report.sample.legitimate} legitimate. {report.sample.failed} failed; {report.sample.notSelected} eligible samples not selected.</p>
        <p className="text-sm">{report.execution}</p>
        <label className="grid max-w-md gap-1 text-sm">Binary policy
          <select className={field} value={policy} onChange={(event) => setPolicy(event.target.value)}>
            <option value="warning">Warning: Caution counts Positive</option>
            <option value="block">Block: Caution counts Negative</option>
          </select>
        </label>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm"><caption className="mb-2 text-left font-semibold">Confusion matrix — raw counts</caption>
            <thead><tr><th className="p-2">Predicted / Actual</th><th className="p-2">Malicious</th><th className="p-2">Legitimate</th></tr></thead>
            <tbody><tr><th className="p-2">Malicious</th><td className="p-2">TP: {metrics.tp}</td><td className="p-2">FP: {metrics.fp}</td></tr>
              <tr><th className="p-2">Legitimate</th><td className="p-2">FN: {metrics.fn}</td><td className="p-2">TN: {metrics.tn}</td></tr></tbody>
          </table>
        </div>
        <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">{['accuracy', 'precision', 'recall', 'f1'].map((key) => <div key={key}><dt className="capitalize">{key}</dt><dd className="text-xl font-semibold">{percent(metrics[key])}</dd></div>)}</dl>
        <p className="text-xs text-slate-500">N/A means a zero denominator. F1 uses the equivalent count formula 2TP / (2TP + FP + FN).</p>
        <details><summary className="cursor-pointer font-semibold">Sampling and limitations</summary><p className="py-2 text-sm">{report.sample.sampling} {report.sample.sourceImportSkippedNote}</p>{report.limitations.map((item) => <p key={item} className="py-1 text-sm">{item}</p>)}</details>
        <h3 className="font-semibold">False positives and false negatives</h3>
        <p className="text-sm">{metrics.fp} false positives; {metrics.fn} false negatives. First 20 cases shown; download includes all cases and available provider evidence.</p>
        {report.errorAnalysis.filter((item) => metrics.falsePositiveIds.includes(item.id) || metrics.falseNegativeIds.includes(item.id)).slice(0, 20).map((item) => <details key={item.id} className="rounded border border-slate-200 p-3 dark:border-slate-700">
          <summary className="cursor-pointer text-sm">{item.id}: expected {item.expected}, predicted {item.prediction}, score {item.score}/100</summary>
          <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-words text-xs">{JSON.stringify(item, null, 2)}</pre>
        </details>)}
        <button onClick={exportReport} className="rounded border border-emerald-600 px-3 py-2 text-sm">Download complete report</button>
      </div>}
      <h3 className="font-semibold">Evaluation history</h3>
      <ul className="space-y-2">{catalog.history.map((item) => <li key={item.id}><button className="text-left text-sm text-emerald-700 dark:text-emerald-300" onClick={() => view(item.id)}>{item.created_at} · {item.dataset} · {item.mode} · {item.status} · {item.processed}/{item.total}</button></li>)}</ul>
      {!catalog.history.length && <p className="text-sm text-slate-500">No evaluations saved yet.</p>}
    </section>
  )
}
