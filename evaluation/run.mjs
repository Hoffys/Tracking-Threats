import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { performance } from 'node:perf_hooks'
import { loadDatasets, datasetHash, EvaluationError } from './dataset.mjs'
import { DEFAULT_THRESHOLDS, compareReports, validateThresholds } from './metrics.mjs'
import { disableNetwork } from './offline.mjs'
import { loadScanners } from './scanners.mjs'
import { makeReport, renderMarkdown } from './report.mjs'

export const fixturePaths = [new URL('./fixtures/tuning.jsonl', import.meta.url), new URL('./fixtures/held-out.jsonl', import.meta.url)]
function options(args) {
  const settings = { command: 'run', datasets: [], split: 'tuning', scanner: 'current', thresholds: { ...DEFAULT_THRESHOLDS } }
  if (args[0] && !args[0].startsWith('--')) settings.command = args.shift()
  if (!['run', 'validate'].includes(settings.command)) throw new EvaluationError('Command must be run or validate')
  const seen = new Set()
  while (args.length) {
    const key = args.shift(), value = args.shift()
    if (!['--dataset', '--split', '--scanner', '--out', '--markdown', '--baseline', '--warning-below', '--block-at-most'].includes(key) || !value || value.startsWith('--')) throw new EvaluationError('Invalid option or missing option value')
    if (key !== '--dataset' && seen.has(key)) throw new EvaluationError('Duplicate command option')
    seen.add(key)
    if (key === '--dataset') settings.datasets.push(value)
    else if (key === '--warning-below') settings.thresholds.warningBelow = Number(value)
    else if (key === '--block-at-most') settings.thresholds.blockAtMost = Number(value)
    else settings[key.slice(2)] = value
  }
  if (!['all', 'tuning', 'held-out'].includes(settings.split)) throw new EvaluationError('Split must be tuning, held-out or all')
  if (!['current', 'baseline'].includes(settings.scanner)) throw new EvaluationError('Scanner must be current or baseline')
  validateThresholds(settings.thresholds)
  return settings
}

export async function main(args = process.argv.slice(2)) {
  const settings = options([...args])
  const rows = loadDatasets(settings.datasets.length ? settings.datasets : fixturePaths)
  const fingerprint = datasetHash(rows)
  if (settings.command === 'validate') {
    console.log(JSON.stringify({ valid: true, rows: rows.length, datasetHash: fingerprint, splits: Object.fromEntries(['tuning', 'held-out'].map((split) => [split, rows.filter((row) => row.split === split).length])) }))
    return
  }
  const outputs = [settings.out, settings.markdown].filter(Boolean).map((path) => resolve(path))
  if (new Set(outputs).size !== outputs.length || outputs.some(existsSync)) throw new EvaluationError('Output already exists or output paths collide; use new paths')
  const selected = rows.filter((row) => settings.split === 'all' || row.split === settings.split)
  if (!selected.length) throw new EvaluationError('Selected split has no cases')
  disableNetwork()
  const scanners = await loadScanners(settings.scanner)
  const predictions = []
  for (const row of selected) {
    let result, latencyMs
    try {
      const start = performance.now()
      result = scanners.functions[row.kind](row.input)
      if (result && typeof result.then === 'function') result = await result
      latencyMs = performance.now() - start
    } catch { throw new EvaluationError(`Scanner failed for case ${row.id}; raw error suppressed`) }
    predictions.push({ id: row.id, split: row.split, kind: row.kind, label: row.label, score: result?.score, status: result?.status, latencyMs })
  }
  scanners.verifyUnchanged()
  const report = makeReport(selected, predictions, { scanner: settings.scanner, source: scanners.source, selectedSplit: settings.split, datasetHash: fingerprint }, settings.thresholds)
  if (settings.baseline) {
    let baseline
    try { baseline = JSON.parse(readFileSync(settings.baseline, 'utf8').replace(/^\uFEFF/, '')) } catch { throw new EvaluationError('Could not read baseline report') }
    report.comparison = compareReports(baseline, report)
  }
  if (settings.out) {
    mkdirSync(dirname(settings.out), { recursive: true })
    writeFileSync(settings.out, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' })
  }
  const markdown = renderMarkdown(report)
  if (settings.markdown) {
    mkdirSync(dirname(settings.markdown), { recursive: true })
    writeFileSync(settings.markdown, markdown, { flag: 'wx' })
  }
  console.log(markdown)
  return report
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(error instanceof EvaluationError ? error.message : 'Evaluation failed; raw error suppressed to protect dataset content')
    process.exitCode = 1
  })
}
