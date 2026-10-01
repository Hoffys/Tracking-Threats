import assert from 'node:assert/strict'
import test from 'node:test'
import { prepareEvaluation, executeEvaluation } from './workflow.mjs'
import { scanUrl } from '../backend/services/urlScanner.js'
import { detectUrl } from '../backend/services/detectionPipeline.js'
import { extractImageIndicators } from '../src/utils/imageInspection.js'
import { detectFile } from '../backend/services/detectionPipeline.js'

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

test('production evaluation calls shared detector and records disabled checks honestly', async () => {
  const old = process.env.REPUTATION_ENABLED
  process.env.REPUTATION_ENABLED = 'false'
  try {
    const prepared = prepareEvaluation({ mode: 'production', limit: 2 })
    prepared.selected = prepared.selected.filter((row) => row.kind === 'url')
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
