import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { isIP } from 'node:net'

export const sha256 = (value) => createHash('sha256').update(value).digest('hex')
const token = /^[a-zA-Z0-9_-]{1,100}$/
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)
const nonempty = (value) => typeof value === 'string' && value.trim().length > 0
const exactKeys = (value, keys) => Object.keys(value).every((key) => keys.includes(key))

export class EvaluationError extends Error {}
const invalid = (location, reason) => { throw new EvaluationError(`${location}: ${reason}`) }

export function normalizeDomain(value) {
  if (typeof value !== 'string' || !value || /[\s/@?#\\]/u.test(value)) throw new Error('Invalid domain')
  const host = new URL(`https://${value}`).hostname.toLowerCase().replace(/\.$/, '')
  if (value.includes(':') && !isIP(host.replace(/^\[|\]$/g, ''))) throw new Error('Domain must exclude port')
  if (!isIP(host.replace(/^\[|\]$/g, '')) && (!host.includes('.') || !/^[a-z0-9.-]+$/.test(host) || host.split('.').some((part) => !part || part.startsWith('-') || part.endsWith('-')))) throw new Error('Invalid domain')
  return host
}

// Deliberately conservative: co.uk and github.io each form one group. No PSL,
// DNS, redirects, reputation providers, or other network services are used.
export function domainGroup(host) {
  const canonical = normalizeDomain(host)
  return isIP(canonical.replace(/^\[|\]$/g, '')) ? canonical : canonical.split('.').slice(-2).join('.')
}

export function observedDomains(row) {
  const hosts = new Set()
  const add = (value) => { hosts.add(normalizeDomain(value)) }
  let text = typeof row.input === 'string' ? row.input : Object.values(row.input).join('\n')
  if (row.kind === 'url') {
    const url = new URL(text.includes('://') ? text : `https://${text}`)
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only HTTP(S) URL inputs are supported')
    add(url.hostname)
  }
  text = text.replace(/https?:\/\/[^\s<>"']+/giu, (candidate) => {
    const url = new URL(candidate.replace(/[),;.!]+$/, ''))
    add(url.hostname)
    // Explicit nested redirect destinations also participate in split checks.
    for (const value of url.searchParams.values()) {
      if (/^https?:\/\//i.test(value)) add(new URL(value).hostname)
    }
    return ' '
  })
  for (const [host] of text.matchAll(/(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?\.)+[\p{L}]{2,63}/gu)) add(host)
  return [...hosts]
}

export function validateRows(rows) {
  if (!Array.isArray(rows) || rows.length === 0) invalid('dataset', 'no rows')
  const ids = new Set()
  const domains = new Map()
  const scenarios = new Map()
  const inputs = new Map()
  const result = rows.map((row, index) => {
    const location = `row ${index + 1}` // Never echo invalid/private input, IDs or parser messages.
    if (!object(row) || !exactKeys(row, ['id', 'split', 'kind', 'label', 'scenario', 'domains', 'input', 'provenance'])) invalid(location, 'invalid row fields')
    if (typeof row.id !== 'string' || !token.test(row.id)) invalid(location, 'id must be an opaque alphanumeric/hyphen/underscore token')
    if (ids.has(row.id)) invalid(location, 'duplicate ID')
    ids.add(row.id)
    if (!['tuning', 'held-out'].includes(row.split)) invalid(location, 'split must be tuning or held-out')
    if (!['url', 'message', 'email'].includes(row.kind)) invalid(location, 'unsupported kind')
    if (!['legitimate', 'phishing'].includes(row.label)) invalid(location, 'unsupported label')
    if (typeof row.scenario !== 'string' || !token.test(row.scenario)) invalid(location, 'scenario must be an opaque group token')
    if (scenarios.has(row.scenario) && scenarios.get(row.scenario) !== row.split) invalid(location, 'scenario overlaps splits')
    scenarios.set(row.scenario, row.split)
    if (row.kind === 'email') {
      if (!object(row.input) || !exactKeys(row.input, ['sender', 'subject', 'body']) || !['sender', 'subject', 'body'].every((key) => typeof row.input[key] === 'string') || !nonempty(row.input.sender) || !nonempty(row.input.subject + row.input.body)) invalid(location, 'email input requires sender, subject and body strings')
    } else if (!nonempty(row.input)) invalid(location, 'input must be a nonempty string')
    const p = row.provenance
    if (!object(p) || !exactKeys(p, ['type', 'source', 'method', 'rationale']) || !nonempty(p.source) || !nonempty(p.rationale)) invalid(location, 'label provenance source and rationale required')
    if (p.type === 'synthetic') {
      if (p.method !== 'scenario-author') invalid(location, 'synthetic labels must identify scenario authorship')
    } else if (p.type === 'external-labeled') {
      if (!['independent-human', 'independent-source'].includes(p.method)) invalid(location, 'external labels must be independent of this detector')
    } else invalid(location, 'unsupported provenance type')
    if (!Array.isArray(row.domains) || row.domains.some((domain) => typeof domain !== 'string')) invalid(location, 'domains must be an array')
    let canonical, observed
    try {
      canonical = row.domains.map(normalizeDomain)
      observed = observedDomains(row)
    } catch { invalid(location, 'invalid domain or URL; no input echoed') }
    if (new Set(canonical).size !== canonical.length) invalid(location, 'duplicate domain in row')
    if (observed.some((host) => !canonical.includes(host))) invalid(location, 'domains must include every observable hostname')
    for (const host of canonical) {
      const group = domainGroup(host)
      if (domains.has(group) && domains.get(group) !== row.split) invalid(location, 'domain group overlaps splits')
      domains.set(group, row.split)
    }
    const normalizedInput = row.kind === 'email' ? ['sender', 'subject', 'body'].map((key) => row.input[key].trim()) : row.input.trim()
    const inputHash = sha256(JSON.stringify([row.kind, normalizedInput]))
    if (inputs.has(inputHash) && inputs.get(inputHash) !== row.split) invalid(location, 'identical input overlaps splits')
    inputs.set(inputHash, row.split)
    return { ...row, domains: canonical }
  })
  return result
}

export function loadDatasets(paths) {
  const rows = []
  paths.forEach((path, fileIndex) => {
    let text
    try { text = readFileSync(path, 'utf8').replace(/^\uFEFF/, '') } catch { invalid(`dataset ${fileIndex + 1}`, 'could not read file') }
    const lines = text.split(/\r?\n/)
    if (lines.at(-1) === '') lines.pop()
    for (const [lineIndex, line] of lines.entries()) {
      let row
      try { row = JSON.parse(line) } catch { invalid(`dataset ${fileIndex + 1}, line ${lineIndex + 1}`, 'invalid JSONL') }
      rows.push(row)
    }
  })
  return validateRows(rows)
}

export function datasetHash(rows) {
  // Stable across file order, whitespace and property ordering; includes all labels and inputs.
  const stable = (value) => Array.isArray(value) ? value.map(stable) : object(value) ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])])) : value
  return sha256(JSON.stringify(rows.toSorted((a, b) => a.id.localeCompare(b.id)).map(stable)))
}
