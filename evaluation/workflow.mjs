import { existsSync } from 'node:fs'
import { performance } from 'node:perf_hooks'
import { loadDatasets, datasetHash, sha256, EvaluationError } from './dataset.mjs'
import { makeReport } from './report.mjs'
import { productionDetectors, localDetectors } from '../backend/services/detectionPipeline.js'
import { scannerGraph } from './scanners.mjs'

const syntheticPaths = [new URL('./fixtures/tuning.jsonl', import.meta.url), new URL('./fixtures/held-out.jsonl', import.meta.url)]
const phiusiilPath = () => process.env.EVALUATION_PHIUSIIL_PATH || new URL('../.evaluation-data/phiusiil-2024-sample.jsonl', import.meta.url)
export const binaryPolicy = 'Primary warning: Appears Safe (80–100) = Negative; Caution (>50 and <80) and Risk Detected (0–50) = Positive. Secondary block: Caution = Negative. Scores are safety scores, not probabilities.'

export function datasetCatalog() {
  return [
    { id: 'synthetic', name: 'Synthetic regression', available: true, purpose: 'Development/regression, not real-world accuracy' },
    { id: 'phiusiil', name: 'UCI PhiUSIIL held-out', available: existsSync(phiusiilPath()), purpose: 'Externally labeled sample; tuning rows excluded. Previously examined holdout, not a fresh blind test.' },
  ]
}

export function prepareEvaluation({ dataset = 'synthetic', mode = 'production', limit } = {}) {
  if (!['synthetic', 'phiusiil'].includes(dataset) || !['production', 'local'].includes(mode)) throw new EvaluationError('Unknown dataset or detector mode')
  const all = loadDatasets(dataset === 'synthetic' ? syntheticPaths : [phiusiilPath()])
  const eligible = dataset === 'phiusiil' ? all.filter((row) => row.split === 'held-out') : all
  if (!eligible.length) throw new EvaluationError('No eligible samples')
  if (eligible.some((row) => dataset === 'synthetic' ? row.provenance.type !== 'synthetic' : row.provenance.type !== 'external-labeled')) throw new EvaluationError('Synthetic and external labels must remain separate')
  const maximum = mode === 'production' ? 100 : 5000
  const count = limit === undefined ? Math.min(eligible.length, mode === 'production' ? 20 : maximum) : Number(limit)
  if (!Number.isInteger(count) || count < 2 || count > maximum) throw new EvaluationError(`Sample limit must be an integer from 2 to ${maximum}`)
  // Labels select a stratified sample only. Detectors below receive input alone.
  const groups = ['phishing', 'legitimate'].map((label) => eligible.filter((row) => row.label === label)
    .sort((a, b) => sha256(a.id).localeCompare(sha256(b.id))))
  const ordered = []
  for (let index = 0; index < Math.max(...groups.map((group) => group.length)); index++) {
    for (const group of groups) if (group[index]) ordered.push(group[index])
  }
  return { dataset, mode, all, eligible, selected: ordered.slice(0, count), requested: count }
}

const redact = (value) => String(value ?? '').replace(/https?:\/\/[^\s<>"']+/gi, '[URL redacted]').replace(/[\w.+-]+@[\w.-]+/g, '[email redacted]').slice(0, 500)
const urlRuleCodes = ['invalid-url', 'brand-impersonation', 'url-userinfo', 'deceptive-userinfo', 'credential-lure', 'ip-destination', 'contextual-idn', 'unencrypted-context', 'external-url-model']
function diagnostics(row, result) {
  const findings = result.details?.findings ?? []
  const codes = findings.map((finding) => finding.code)
  const providers = (result.details?.threatIntel ?? []).map((provider) => ({
    provider: provider.provider, checked: provider.checked === true,
    found: provider.checked && !provider.error && !provider.skipped ? Boolean(provider.found) : null,
    error: provider.error ? redact(provider.error) : null,
    skipped: provider.skipped ? redact(provider.skipped) : null,
    warning: provider.warning ? redact(provider.warning) : null,
    deduction: provider.deduction ?? 0,
    redirects: provider.redirects?.map((item) => typeof item === 'string' ? '[origin redacted]' : { from: '[origin redacted]', to: '[origin redacted]' }),
    inspection: provider.inspection ? Object.fromEntries(['passwordFields', 'externalFormActions', 'hiddenFrames', 'credentialLanguage', 'obfuscatedScripts', 'formCount'].filter((key) => key in provider.inspection).map((key) => [key, provider.inspection[key]])) : null,
  }))
  return {
    id: row.id, inputReference: `Dataset case ${row.id} (raw input omitted)`,
    expected: row.label, prediction: result.status, score: result.score,
    triggeredIndicators: findings.map(({ code, label, deduction }) => ({ code, label: redact(label), deduction })),
    warnings: (result.warningSigns ?? []).map(redact),
    notTriggered: row.kind === 'url' ? urlRuleCodes.filter((code) => !codes.includes(code)) : [],
    notTriggeredNote: row.kind === 'url' ? 'Local rule codes absent from actual findings; absence does not establish safety.' : 'This detector does not expose an exhaustive non-triggered rule trace.',
    providers, coverage: result.details?.coverage ?? null,
  }
}

export async function executeEvaluation(prepared, onProgress = async () => {}) {
  const { dataset, mode, all, eligible, selected, requested } = prepared
  const detectors = mode === 'production' ? productionDetectors : localDetectors
  const source = scannerGraph('current', mode === 'production')
  const predictions = [], completedRows = [], analyses = [], failures = []
  for (const row of selected) {
    try {
      const start = performance.now()
      // Keep labels, provenance, split and IDs completely outside the detector.
      const result = await detectors[row.kind](structuredClone(row.input))
      const prediction = { id: row.id, split: row.split, kind: row.kind, label: row.label, score: result.score, status: result.status, latencyMs: performance.now() - start }
      // Validate before accepting the sample into a denominator.
      makeReport([row], [prediction])
      predictions.push(prediction)
      completedRows.push(row)
      analyses.push(diagnostics(row, result))
    } catch {
      failures.push({ id: row.id, reason: 'Detector failed; no prediction fabricated; excluded from metrics' })
    }
    await onProgress(predictions.length + failures.length, selected.length)
  }
  if (JSON.stringify(source.files) !== JSON.stringify(scannerGraph('current', mode === 'production').files)) throw new EvaluationError('Detector changed during evaluation; rerun')
  const report = makeReport(completedRows, predictions, { scanner: `production-shared/${mode}`, source: { files: source.files }, selectedSplit: dataset === 'phiusiil' ? 'held-out' : 'all', datasetHash: datasetHash(selected) })
  const misses = new Set(['warning', 'block'].flatMap((policy) => [...report.metrics.overall[policy].falseNegativeIds, ...report.metrics.overall[policy].falsePositiveIds]))
  return {
    ...report, policy: binaryPolicy, dataset, mode,
    execution: mode === 'production' ? 'Same production detection pipeline including configured providers, page inspection, and email authentication. Administrative allowlist overrides and persistence/notification side effects are excluded.' : 'Same production local detector functions only. Online reputation, page inspection and email authentication were NOT run.',
    sample: { imported: all.length, eligible: eligible.length, requested, selected: selected.length,
      evaluated: predictions.length, phishing: completedRows.filter((row) => row.label === 'phishing').length,
      legitimate: completedRows.filter((row) => row.label === 'legitimate').length,
      excludedTuning: dataset === 'phiusiil' ? all.length - eligible.length : 0,
      notSelected: eligible.length - selected.length, failed: failures.length, invalidLoadedRows: 0,
      sourceImportSkipped: dataset === 'phiusiil' ? null : 0,
      sourceImportSkippedNote: dataset === 'phiusiil' ? 'Original importer did not retain source skip counts; unknown, not zero.' : 'Validated internal fixtures',
      unreachablePageChecks: analyses.filter((item) => item.providers.some((provider) => provider.provider === 'Page inspection' && provider.error)).length,
      sampling: 'Deterministic alternating labels, ordered within label by SHA-256(case ID); no PRNG seed. Existing PhiUSIIL importer used SHA-256(URL), one URL per domain group.', seed: null,
      source: dataset === 'phiusiil' ? 'https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset' : 'evaluation/fixtures',
    },
    limitations: [
      'No new ML or threshold tuning. Existing active lexical model was trained on PhiUSIIL tuning rows; held-out rows were previously examined and are not a fresh blind test.',
      'Unavailable reputation/page checks do not remove a prediction from metrics and never count as successful clean checks.',
      'Original PhiUSIIL source import exclusions are unknown. Only the selected validated sample is evaluated.',
    ],
    failures, analyses, errorAnalysis: analyses.filter((item) => misses.has(item.id)),
  }
}
