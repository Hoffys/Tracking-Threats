// Derive a report from the original recorded predictions; never rerun detectors.
import { readFileSync, writeFileSync } from 'node:fs'
import { loadDatasets, sha256, EvaluationError } from './dataset.mjs'
import { fixturePaths } from './run.mjs'
import { verifyFrozenSources } from './scanners.mjs'
import { makeReport, renderMarkdown } from './report.mjs'

const capture = JSON.parse(readFileSync(new URL('./baseline/predictions.json', import.meta.url), 'utf8'))
verifyFrozenSources()
for (const dataset of capture.datasets) {
  if (sha256(readFileSync(new URL(`./fixtures/${dataset.split}.jsonl`, import.meta.url))) !== dataset.sha256) throw new EvaluationError('Frozen fixture hash mismatch')
}
const report = makeReport(loadDatasets(fixturePaths), capture.predictions, {
  capturedAt: capture.capturedAt, nodeVersion: capture.nodeVersion, scanner: 'baseline',
  source: capture.sourceManifest,
})
writeFileSync(new URL('./baseline/report.json', import.meta.url), JSON.stringify(report, null, 2) + '\n', { flag: 'wx' })
writeFileSync(new URL('./baseline/report.md', import.meta.url), renderMarkdown(report), { flag: 'wx' })
console.log(renderMarkdown(report))
