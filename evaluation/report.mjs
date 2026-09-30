import { datasetHash, EvaluationError } from './dataset.mjs'
import { DEFAULT_THRESHOLDS, decisions, summarize } from './metrics.mjs'

export function makeReport(rows, predictions, metadata = {}, thresholds = DEFAULT_THRESHOLDS) {
  if (rows.length !== predictions.length || new Set(predictions.map((p) => p.id)).size !== rows.length) throw new EvaluationError('Prediction count or IDs do not match dataset selection')
  const expected = new Map(rows.map((row) => [row.id, row]))
  const safePredictions = predictions.map((prediction) => {
    const row = expected.get(prediction.id)
    if (!row || ['kind', 'label', 'split'].some((key) => row[key] !== prediction[key])) throw new EvaluationError('Prediction identity does not match dataset row')
    if (!['Safe', 'Suspicious', 'Dangerous', 'Blocked'].includes(prediction.status)) throw new EvaluationError('Scanner returned unsupported status')
    // Strict allowlist: never serialize scanner details, recommendations or URLs.
    return { id: row.id, split: row.split, kind: row.kind, label: row.label, score: prediction.score, status: prediction.status, ...decisions(prediction.score, thresholds), latencyMs: prediction.latencyMs }
  })
  const synthetic = rows.filter((row) => row.provenance.type === 'synthetic').length
  return {
    schemaVersion: 1,
    capturedAt: metadata.capturedAt ?? new Date().toISOString(),
    nodeVersion: metadata.nodeVersion ?? process.version,
    scanner: metadata.scanner ?? 'unspecified',
    source: metadata.source ?? null,
    datasetHash: metadata.datasetHash ?? datasetHash(rows),
    selectedSplit: metadata.selectedSplit ?? 'all',
    evidence: {
      syntheticRows: synthetic, externallyLabeledRows: rows.length - synthetic,
      statement: synthetic === rows.length
        ? 'SYNTHETIC regression fixtures only. These metrics are not real-world accuracy estimates. Independent real-world evaluation is outstanding.'
        : 'External label independence is asserted by the importer, not verified by tooling. Dataset-specific metrics do not establish real-world accuracy; review sampling, provenance and temporal/organizational leakage.',
    },
    thresholds: { ...thresholds },
    policy: 'Scores are safety scores: warning = score < warningBelow (includes blocks); block = score <= blockAtMost. Thresholds are evaluator policies, not production configuration changes.',
    latencyMethod: 'One serial call per case using performance.now(), in milliseconds; imports, validation and reporting excluded. No warmup; order, JIT, host load and instrumentation affect timings. Not endpoint/network or throughput latency.',
    metrics: summarize(safePredictions, thresholds), predictions: safePredictions,
  }
}

const percent = (value) => value === null ? 'undefined' : `${(value * 100).toFixed(2)}%`
export function renderMarkdown(report) {
  const rows = [
    '# Detection evaluation', '', report.evidence.statement, '',
    `Captured: ${report.capturedAt}. Scanner: ${report.scanner}. Selected split: ${report.selectedSplit}.`, '',
    `Dataset fingerprint: \`${report.datasetHash}\`.`, '', report.policy, '',
    '| Split | Policy | TP | FP | TN | FN | Precision | Recall | FPR |',
    '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
  ]
  for (const [split, metrics] of Object.entries(report.metrics.bySplit)) {
    if (!metrics.count) continue
    for (const policy of ['warning', 'block']) {
      const m = metrics[policy]
      rows.push(`| ${split} | ${policy} | ${m.tp} | ${m.fp} | ${m.tn} | ${m.fn} | ${percent(m.precision)} | ${percent(m.recall)} | ${percent(m.fpr)} |`)
    }
  }
  rows.push('', 'Undefined ratios have a zero denominator; they are not silently converted to zero or 100%.', '', report.latencyMethod, '', '| Split | Calls | Mean ms | P50 ms | P95 ms | Max ms |', '| --- | ---: | ---: | ---: | ---: | ---: |')
  for (const [split, metrics] of Object.entries(report.metrics.bySplit)) {
    if (!metrics.count) continue
    const m = metrics.latency
    rows.push(`| ${split} | ${m.count} | ${m.meanMs.toFixed(4)} | ${m.p50Ms.toFixed(4)} | ${m.p95Ms.toFixed(4)} | ${m.maxMs.toFixed(4)} |`)
  }
  if (report.comparison) {
    rows.push('', '## Comparison with frozen baseline', '', 'Differences are current minus baseline; rate changes below are percentage points. A negative recall change or positive FPR change is a regression. Latency differences are descriptive, not a controlled performance benchmark.', '', '| Split | Policy | ΔTP | ΔFP | ΔTN | ΔFN | ΔPrecision pp | ΔRecall pp | ΔFPR pp |', '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |')
    for (const [split, deltas] of Object.entries(report.comparison.delta.bySplit)) {
      if (!report.metrics.bySplit[split].count) continue
      for (const policy of ['warning', 'block']) {
        const m = deltas[policy], pp = (v) => v === null ? 'undefined' : (100 * v).toFixed(2)
        rows.push(`| ${split} | ${policy} | ${m.tp} | ${m.fp} | ${m.tn} | ${m.fn} | ${pp(m.precision)} | ${pp(m.recall)} | ${pp(m.fpr)} |`)
      }
    }
    rows.push('', `${report.comparison.changed.length} cases changed score or status. JSON includes baseline/current metrics, deltas, and changed case IDs.`)
  }
  rows.push('', '## Misses and false positives (IDs only)', '')
  for (const [split, metrics] of Object.entries(report.metrics.bySplit)) {
    if (!metrics.count) continue
    for (const policy of ['warning', 'block']) rows.push(`- ${split}, ${policy}: FP = ${metrics[policy].falsePositiveIds.join(', ') || 'none'}; FN = ${metrics[policy].falseNegativeIds.join(', ') || 'none'}.`)
  }
  return rows.join('\n') + '\n'
}
