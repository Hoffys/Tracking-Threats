import '../backend/config/loadEnv.js'
import { mkdirSync, writeFileSync, existsSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { prepareEvaluation, executeEvaluation } from './workflow.mjs'
import { renderMarkdown } from './report.mjs'

const args = process.argv.slice(2)
const settings = {}
while (args.length) {
  const key = args.shift(), value = args.shift()
  if (!['--dataset', '--mode', '--limit', '--out'].includes(key) || !value) throw new Error('Use --dataset synthetic|phiusiil --mode local|production --limit N --out new-file.json')
  settings[key.slice(2)] = value
}
if (!settings.out) throw new Error('--out is required')
const output = resolve(settings.out)
const markdown = `${output}.md`
if (existsSync(output) || existsSync(markdown)) throw new Error('Output exists; use new paths')
const prepared = prepareEvaluation(settings)
console.log(JSON.stringify({ dataset: prepared.dataset, mode: prepared.mode, selected: prepared.selected.length }))
const report = await executeEvaluation(prepared, async (done, total) => {
  if (done % 10 === 0 || done === total) console.log(`${done}/${total} processed`)
})
mkdirSync(dirname(output), { recursive: true })
writeFileSync(output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' })
writeFileSync(markdown, renderMarkdown(report), { flag: 'wx' })
console.log(JSON.stringify({ output, sample: report.sample, warning: report.metrics.overall.warning, block: report.metrics.overall.block }, (key, value) => key.endsWith('Ids') ? undefined : value))
if (report.failures.length) process.exitCode = 1
