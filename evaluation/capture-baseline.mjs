// One-time capture. Refuses to replace baseline predictions.
import { readFileSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { performance } from 'node:perf_hooks'
import { scanUrl } from './baseline/scanners/urlScanner.js'
import { scanMessage } from './baseline/scanners/messageScanner.js'
import { analyzeEmail } from './baseline/scanners/emailAnalyzer.js'

const hash = (value) => createHash('sha256').update(value).digest('hex')
const manifest = JSON.parse(readFileSync(new URL('./baseline/source-manifest.json', import.meta.url), 'utf8').replace(/^\uFEFF/, ''))
for (const file of manifest.files) {
  if (hash(readFileSync(new URL(`./baseline/scanners/${file.source.split(/[\\/]/).at(-1)}`, import.meta.url))) !== file.sha256) throw new Error('Frozen scanner hash mismatch')
}
const datasets = ['tuning', 'held-out'].map((split) => {
  const bytes = readFileSync(new URL(`./fixtures/${split}.jsonl`, import.meta.url))
  return { split, sha256: hash(bytes), rows: bytes.toString('utf8').trim().split('\n').map(JSON.parse) }
})
const predictions = datasets.flatMap(({ rows }) => rows.map((row) => {
  const start = performance.now()
  const result = ({ url: scanUrl, message: scanMessage, email: analyzeEmail })[row.kind](row.input)
  const latencyMs = performance.now() - start
  return { id: row.id, split: row.split, kind: row.kind, label: row.label, score: result.score, status: result.status, latencyMs }
}))
writeFileSync(new URL('./baseline/predictions.json', import.meta.url), JSON.stringify({
  schemaVersion: 1, capturedAt: new Date().toISOString(), nodeVersion: process.version,
  statement: 'SYNTHETIC regression cases; these results are not real-world accuracy estimates.',
  sourceManifest: manifest, datasets: datasets.map(({ split, sha256 }) => ({ split, sha256 })), predictions,
}, null, 2) + '\n', { flag: 'wx' })
console.log(`Frozen ${predictions.length} baseline predictions.`)
