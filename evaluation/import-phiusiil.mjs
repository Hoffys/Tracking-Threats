import { createReadStream, createWriteStream } from 'node:fs'
import { mkdir } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { createHash } from 'node:crypto'
import { parse } from 'csv-parse'
import { getDomain } from 'tldts'
import { domainGroup, observedDomains } from './dataset.mjs'

const [input, output, requested = '500'] = process.argv.slice(2)
const perLabel = Number.parseInt(requested, 10)
if (!input || !output || !Number.isInteger(perLabel) || perLabel < 50 || perLabel > 5000) {
  throw new Error('Usage: node evaluation/import-phiusiil.mjs <csv> <output.jsonl> <50-5000 per label>')
}

const candidates = { phishing: [], legitimate: [] }
const seenUrls = new Set()
for await (const row of createReadStream(resolve(input)).pipe(parse({ columns: true, bom: true, relax_quotes: true }))) {
  const url = String(row.URL ?? '').trim()
  const label = String(row.label ?? '') === '0' ? 'phishing' : String(row.label ?? '') === '1' ? 'legitimate' : null
  if (!label || !url || url.length > 8192 || seenUrls.has(url)) continue
  try {
    const parsed = new URL(url)
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) continue
    const group = getDomain(parsed.hostname, { allowPrivateDomains: true }) ?? parsed.hostname
    const domains = observedDomains({ kind: 'url', input: url })
    const groups = [...new Set(domains.map(domainGroup))]
    seenUrls.add(url)
    candidates[label].push({ url, hostname: parsed.hostname.toLowerCase(), group, domains, groups,
      order: createHash('sha256').update(url).digest('hex') })
  } catch { /* Invalid source URL; omit without relabeling. */ }
}

const selected = []
const usedGroups = new Set()
for (const label of ['phishing', 'legitimate']) {
  let selectedForLabel = 0
  for (const item of candidates[label].sort((a, b) => a.order.localeCompare(b.order))) {
    if (item.groups.some((group) => usedGroups.has(group))) continue
    item.groups.forEach((group) => usedGroups.add(group))
    selected.push({ ...item, label, split: selectedForLabel < perLabel ? 'tuning' : 'held-out' })
    selectedForLabel += 1
    if (selectedForLabel === perLabel * 2) break
  }
  if (selectedForLabel !== perLabel * 2) {
    throw new Error(`Not enough unique ${label} domain groups for requested tuning and held-out samples`)
  }
}

selected.sort((a, b) => a.order.localeCompare(b.order))
await mkdir(dirname(resolve(output)), { recursive: true })
const stream = createWriteStream(resolve(output), { flags: 'w' })
for (const [index, item] of selected.entries()) {
  const id = `phiusiil-${String(index + 1).padStart(4, '0')}`
  const row = {
    id, split: item.split, kind: 'url', label: item.label,
    scenario: `phiusiil-domain-${item.order.slice(0, 16)}`,
    domains: item.domains, input: item.url,
    provenance: {
      type: 'external-labeled',
      source: 'UCI PhiUSIIL Phishing URL Dataset, donated 2024-03-03, DOI 10.1016/j.cose.2023.103545, CC BY 4.0',
      method: 'independent-source',
      rationale: `Source dataset label ${item.label === 'phishing' ? '0' : '1'}; one deterministic URL per registrable domain`,
    },
  }
  stream.write(JSON.stringify(row) + '\n')
}
await new Promise((resolveStream, reject) => stream.end((error) => error ? reject(error) : resolveStream()))
console.log(JSON.stringify({ output: resolve(output), rows: selected.length, perLabelPerSplit: perLabel, uniqueDomainGroups: usedGroups.size }))
