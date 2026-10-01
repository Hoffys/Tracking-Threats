import { readFileSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
const base = 'https://tracking-threats-production.up.railway.app'
const report = { at: new Date().toISOString(), base, checks: [], note: 'Read-only check of existing deployment. Local audit changes are not deployed.' }
for (const path of ['/api/health', '/', '/ocr/worker.min.js', '/ocr/eng.traineddata.gz', '/ocr/tesseract-core-simd-lstm.wasm.js']) {
  try {
    const response = await fetch(base + path, { signal: AbortSignal.timeout(20000) })
    const bytes = Buffer.from(await response.arrayBuffer())
    const item = { path, status: response.status, type: response.headers.get('content-type'), bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') }
    if (path === '/api/health') item.body = JSON.parse(bytes.toString())
    if (path === '/') {
      item.assets = [...bytes.toString().matchAll(/src="([^"]+)/g)].map((match) => match[1])
      item.csp = response.headers.get('content-security-policy')
    }
    if (path.startsWith('/ocr/')) item.matchesLocal = bytes.equals(readFileSync(new URL(`../public${path}`, import.meta.url)))
    report.checks.push(item)
  } catch (error) { report.checks.push({ path, error: error.message }) }
}
writeFileSync(new URL('./results/audit-production-health.json', import.meta.url), JSON.stringify(report, null, 2) + '\n')
console.log(JSON.stringify(report, null, 2))
