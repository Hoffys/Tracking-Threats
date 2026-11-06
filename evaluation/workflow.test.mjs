import assert from 'node:assert/strict'
import test from 'node:test'
import { prepareEvaluation, executeEvaluation, selectEvaluationRows } from './workflow.mjs'
import { scanUrl } from '../backend/services/urlScanner.js'
import { detectUrl } from '../backend/services/detectionPipeline.js'
import { extractImageIndicators } from '../src/utils/imageInspection.js'
import { detectFile } from '../backend/services/detectionPipeline.js'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

test('changing ground truth changes the matrix but never the detector prediction', async () => {
  const prepared = prepareEvaluation({ mode: 'local', limit: 2 })
  const first = await executeEvaluation(prepared)
  const inverted = { ...prepared, selected: prepared.selected.map((row) => ({ ...row, label: row.label === 'phishing' ? 'legitimate' : 'phishing' })) }
  const second = await executeEvaluation(inverted)
  assert.deepEqual(first.predictions.map(({ id, score, status }) => ({ id, score, status })), second.predictions.map(({ id, score, status }) => ({ id, score, status })))
  assert.notDeepEqual(first.metrics.overall.warning, second.metrics.overall.warning)
  assert.equal(first.sample.evaluated, 2)
  assert.equal(first.sample.failed, 0)
})

test('limited selections are repeatable and independent of expected labels', () => {
  const first = prepareEvaluation({ dataset: 'synthetic-reviewed-v2', mode: 'local', limit: 17 })
  const repeated = prepareEvaluation({ dataset: 'synthetic-reviewed-v2', mode: 'local', limit: 17 })
  const relabeled = first.eligible.map((row) => ({ ...row, label: row.label === 'phishing' ? 'legitimate' : 'phishing' }))
  const ids = (rows) => rows.map((row) => row.id)
  assert.deepEqual(ids(first.selected), ids(repeated.selected))
  assert.deepEqual(ids(first.selected), ids(selectEvaluationRows(relabeled, 17)))
})

test('production evaluation calls shared detector and records disabled checks honestly', async () => {
  const old = process.env.REPUTATION_ENABLED
  process.env.REPUTATION_ENABLED = 'false'
  try {
    const prepared = prepareEvaluation({ mode: 'production', limit: 60 })
    prepared.selected = prepared.eligible.filter((row) => row.kind === 'url').slice(0, 2)
    prepared.requested = prepared.selected.length
    const report = await executeEvaluation(prepared)
    for (const row of prepared.selected) {
      const direct = await detectUrl(row.input)
      const prediction = report.predictions.find((item) => item.id === row.id)
      assert.equal(prediction.score, direct.score)
      assert.equal(prediction.status, direct.status)
    }
    assert.ok(report.analyses.length > 0)
    assert.ok(report.analyses.every((item) => item.providers.every((provider) => provider.checked === false && provider.found === null)))
    assert.equal(report.sample.failed, 0)
  } finally { if (old === undefined) delete process.env.REPUTATION_ENABLED; else process.env.REPUTATION_ENABLED = old }
})

test('reviewed snapshot predictions are independent of expected labels and benign login remains Safe', async () => {
  const prepared = prepareEvaluation({ dataset: 'synthetic-reviewed-v2', mode: 'local', limit: 60 })
  prepared.selected = prepared.selected.filter((row) => row.pageSnapshot)
  prepared.requested = prepared.selected.length
  const first = await executeEvaluation(prepared)
  const relabeled = { ...prepared, selected: prepared.selected.map((row) => ({ ...row, label: row.label === 'phishing' ? 'legitimate' : 'phishing' })) }
  const second = await executeEvaluation(relabeled)
  assert.deepEqual(first.predictions.map(({ id, score, status }) => ({ id, score, status })), second.predictions.map(({ id, score, status }) => ({ id, score, status })))
  const benign = first.predictions.find((item) => item.id === 'T-url-01')
  const phishing = first.predictions.find((item) => item.id === 'H-url-09')
  assert.equal(benign.status, 'Safe')
  assert.ok(benign.score >= 80)
  assert.equal(phishing.status, 'Dangerous')
  assert.equal(first.sample.failed, 0)
})

test('full reviewed run evaluates every case and retains diagnostic-only cases outside metric denominators', async () => {
  const prepared = prepareEvaluation({ dataset: 'synthetic-reviewed-v2', mode: 'local', limit: 60 })
  assert.equal(prepared.selected.length, prepared.eligible.length)
  assert.deepEqual(prepared.selected.map((row) => row.id).sort(), prepared.eligible.map((row) => row.id).sort())
  const report = await executeEvaluation(prepared)
  assert.equal(report.sample.evaluated, 60)
  assert.equal(report.metrics.overall.count, 54)
  assert.equal(report.metricEligibility.excluded.length, 6)
  assert.equal(report.predictions.length, 60)
  assert.equal(report.analyses.length, 60)
  assert.equal(report.analyses.filter((item) => !item.metricEligible).length, 6)
})

test('controlled snapshots complete with network APIs disabled', () => {
  const cwd = fileURLToPath(new URL('../', import.meta.url))
  const source = `
    import assert from 'node:assert/strict';
    import { disableNetwork } from './evaluation/offline.mjs';
    disableNetwork();
    const { detectUrlOfflineSnapshot } = await import('./backend/services/detectionPipeline.js');
    const result = await detectUrlOfflineSnapshot('https://accounts.google.com/login', { title: 'Google Account sign in', passwordFields: 1, formCount: 1, externalFormActions: 0, hiddenFrames: 0, credentialLanguage: true, obfuscatedScripts: false });
    assert.equal(result.status, 'Safe');
    assert.equal(result.details.threatIntel.length, 1);
    assert.equal(result.details.threatIntel[0].provider, 'Rendered page inspection');
  `
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', source], { cwd, encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
})

test('extracted QR URL reaches real URL detector through file/link pipeline', async () => {
  const old = process.env.REPUTATION_ENABLED
  process.env.REPUTATION_ENABLED = 'false'
  try {
    const url = 'https://paypal.example.test/verify-password'
    const indicators = extractImageIndicators('', [url])
    const result = await detectFile({ fileName: 'qr.png', mimeType: 'image/png', size: 100, content: indicators.scanText })
    assert.ok(scanUrl(url).score < 80)
    assert.ok(result.score <= scanUrl(url).score)
    assert.equal(result.details.coverage.linksChecked, 1)
  } finally { if (old === undefined) delete process.env.REPUTATION_ENABLED; else process.env.REPUTATION_ENABLED = old }
})

test('evaluation rejects unknown modes, dataset paths and excessive live sample counts', () => {
  assert.throws(() => prepareEvaluation({ dataset: '../../.env' }))
  assert.throws(() => prepareEvaluation({ mode: 'fake' }))
  assert.throws(() => prepareEvaluation({ mode: 'production', limit: 101 }))
})
