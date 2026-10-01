import { EvaluationError } from './dataset.mjs'

export const DEFAULT_THRESHOLDS = Object.freeze({ warningBelow: 80, blockAtMost: 50 })
export function validateThresholds(thresholds) {
  if (!thresholds || !Number.isFinite(thresholds.warningBelow) || !Number.isFinite(thresholds.blockAtMost) || thresholds.blockAtMost < 0 || thresholds.warningBelow > 100 || thresholds.blockAtMost >= thresholds.warningBelow) throw new EvaluationError('Require 0 <= block-at-most < warning-below <= 100')
}
export function decisions(score, thresholds = DEFAULT_THRESHOLDS) {
  validateThresholds(thresholds)
  if (!Number.isFinite(score) || score < 0 || score > 100) throw new EvaluationError('Scanner returned invalid safety score')
  return { warning: score < thresholds.warningBelow, block: score <= thresholds.blockAtMost }
}
const ratio = (numerator, denominator) => denominator ? numerator / denominator : null
export function confusion(rows, policy, thresholds = DEFAULT_THRESHOLDS) {
  if (!['warning', 'block'].includes(policy)) throw new EvaluationError('Invalid policy')
  validateThresholds(thresholds)
  let tp = 0, fp = 0, tn = 0, fn = 0
  const falsePositiveIds = [], falseNegativeIds = []
  for (const row of rows) {
    if (!['phishing', 'legitimate'].includes(row.label)) throw new EvaluationError('Invalid prediction label')
    const predicted = decisions(row.score, thresholds)[policy]
    if (row.label === 'phishing') {
      if (predicted) tp++
      else { fn++; falseNegativeIds.push(row.id) }
    } else {
      if (predicted) { fp++; falsePositiveIds.push(row.id) }
      else tn++
    }
  }
  return { tp, fp, tn, fn, accuracy: ratio(tp + tn, tp + tn + fp + fn),
    precision: ratio(tp, tp + fp), recall: ratio(tp, tp + fn),
    f1: ratio(2 * tp, 2 * tp + fp + fn), fpr: ratio(fp, fp + tn), falsePositiveIds, falseNegativeIds }
}
export function latency(rows) {
  const samples = rows.map((row) => row.latencyMs).sort((a, b) => a - b)
  if (samples.some((sample) => !Number.isFinite(sample) || sample < 0)) throw new EvaluationError('Invalid latency sample')
  const percentile = (p) => samples.length ? samples[Math.max(0, Math.ceil(samples.length * p) - 1)] : null
  return { count: samples.length, meanMs: samples.length ? samples.reduce((a, b) => a + b, 0) / samples.length : null, p50Ms: percentile(0.5), p95Ms: percentile(0.95), maxMs: samples.at(-1) ?? null }
}
export function summarize(rows, thresholds = DEFAULT_THRESHOLDS) {
  const group = (items) => ({ count: items.length, warning: confusion(items, 'warning', thresholds), block: confusion(items, 'block', thresholds), latency: latency(items) })
  return {
    overall: group(rows),
    bySplit: Object.fromEntries(['tuning', 'held-out'].map((split) => [split, group(rows.filter((row) => row.split === split))])),
    byKind: Object.fromEntries(['url', 'message', 'email'].map((kind) => [kind, group(rows.filter((row) => row.kind === kind))])),
    bySplitAndKind: Object.fromEntries(['tuning', 'held-out'].flatMap((split) => ['url', 'message', 'email'].map((kind) => [`${split}/${kind}`, group(rows.filter((row) => row.split === split && row.kind === kind))]))),
  }
}

export function compareReports(baseline, current) {
  if (baseline.schemaVersion !== 1 || current.schemaVersion !== 1 || baseline.datasetHash !== current.datasetHash) throw new EvaluationError('Comparison requires identical validated datasets')
  if (baseline.thresholds?.warningBelow !== current.thresholds?.warningBelow || baseline.thresholds?.blockAtMost !== current.thresholds?.blockAtMost) throw new EvaluationError('Comparison requires identical thresholds')
  const previous = new Map(baseline.predictions.map((row) => [row.id, row]))
  if (previous.size !== baseline.predictions.length) throw new EvaluationError('Duplicate baseline prediction IDs')
  const selected = current.predictions.map((row) => {
    const old = previous.get(row.id)
    if (!old || old.kind !== row.kind || old.split !== row.split || old.label !== row.label) throw new EvaluationError('Comparison prediction identities do not match')
    return old
  })
  // Recompute from predictions, never trust possibly stale summary counts.
  const before = summarize(selected, current.thresholds)
  const after = summarize(current.predictions, current.thresholds)
  const difference = (old, now) => Object.fromEntries(['tp', 'fp', 'tn', 'fn', 'accuracy', 'precision', 'recall', 'f1', 'fpr'].map((key) => [key, old[key] === null || now[key] === null ? null : now[key] - old[key]]))
  const delta = (old, now) => ({ warning: difference(old.warning, now.warning), block: difference(old.block, now.block), latencyMeanMs: old.latency.meanMs === null || now.latency.meanMs === null ? null : now.latency.meanMs - old.latency.meanMs })
  return {
    direction: 'current minus baseline; lower FPR is better, higher recall/precision is better; null means undefined',
    baselineCapturedAt: baseline.capturedAt,
    baseline: before, current: after,
    delta: { overall: delta(before.overall, after.overall), ...Object.fromEntries(['bySplit', 'byKind', 'bySplitAndKind'].map((key) => [key, Object.fromEntries(Object.keys(before[key]).map((name) => [name, delta(before[key][name], after[key][name])]))])) },
    changed: current.predictions.flatMap((row) => {
      const old = previous.get(row.id)
      const oldDecision = decisions(old.score, current.thresholds), newDecision = decisions(row.score, current.thresholds)
      return old.score === row.score && old.status === row.status ? [] : [{ id: row.id, label: row.label, beforeScore: old.score, afterScore: row.score, before: oldDecision, after: newDecision }]
    }),
  }
}
