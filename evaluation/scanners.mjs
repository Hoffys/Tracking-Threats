import { readFileSync } from 'node:fs'
import { dirname, isAbsolute, relative, resolve } from 'node:path'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'
import { sha256, EvaluationError } from './dataset.mjs'

const root = fileURLToPath(new URL('../', import.meta.url))
const require = createRequire(import.meta.url)
export function scannerGraph(scanner, production = false) {
  const directory = scanner === 'baseline' ? resolve(root, 'evaluation/baseline/scanners') : resolve(root, 'backend/services')
  const files = new Map()
  function visit(path) {
    if (files.has(path)) return
    const local = relative(root, path)
    if (local.startsWith('..') || isAbsolute(local)) throw new EvaluationError('Scanner import leaves repository')
    const bytes = readFileSync(path)
    files.set(path, sha256(bytes))
    const source = bytes.toString('utf8')
    if (/\bimport\s*\(\s*[^'"\s]/.test(source)) throw new EvaluationError('Computed dynamic scanner imports are not supported')
    const imports = [...source.matchAll(/\b(?:import|export)\s+(?:[^;\n]*?\s+from\s*)?['"]([^'"]+)['"]|\bimport\s*\(\s*['"]([^'"]+)['"]/g)]
    for (const match of imports) {
      const specifier = match[1] ?? match[2]
      if (specifier.startsWith('node:')) continue
      if (specifier === 'tldts') {
        // Reviewed offline PSL parser: its Node entry bundles the suffix tables,
        // performs no network access, and is fingerprinted with the scanners.
        visit(require.resolve('tldts'))
        const manifest = resolve(dirname(require.resolve('tldts')), '../../package.json')
        files.set(manifest, sha256(readFileSync(manifest)))
        continue
      }
      if (!specifier.startsWith('.')) throw new EvaluationError('Evaluation scanners must use relative or node: imports; third-party imports require offline review')
      visit(resolve(dirname(path), specifier))
    }
  }
  for (const name of ['urlScanner.js', 'messageScanner.js', 'emailAnalyzer.js']) visit(resolve(directory, name))
  if (production) visit(resolve(directory, 'detectionPipeline.js'))
  return { directory, files: [...files].map(([path, hash]) => ({ path: relative(root, path).replaceAll('\\', '/'), sha256: hash })).sort((a, b) => a.path.localeCompare(b.path)) }
}
export function verifyFrozenSources() {
  const manifest = JSON.parse(readFileSync(new URL('./baseline/source-manifest.json', import.meta.url), 'utf8').replace(/^\uFEFF/, ''))
  for (const file of manifest.files) {
    const name = file.source.split(/[\\/]/).at(-1)
    if (sha256(readFileSync(new URL(`./baseline/scanners/${name}`, import.meta.url))) !== file.sha256) throw new EvaluationError('Frozen scanner source hash mismatch')
  }
  return manifest
}
export async function loadScanners(scanner) {
  if (scanner === 'baseline') verifyFrozenSources()
  const graph = scannerGraph(scanner)
  const [url, message, email] = await Promise.all(['urlScanner.js', 'messageScanner.js', 'emailAnalyzer.js'].map((name) => import(pathToFileURL(resolve(graph.directory, name)).href)))
  return { functions: { url: url.scanUrl, message: message.scanMessage, email: email.analyzeEmail }, source: { files: graph.files }, verifyUnchanged() {
    if (JSON.stringify(graph.files) !== JSON.stringify(scannerGraph(scanner).files)) throw new EvaluationError('Scanner files changed during evaluation; rerun after edits settle')
  } }
}
