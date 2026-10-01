import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { validateRows, loadDatasets, datasetHash, domainGroup, observedDomains } from './dataset.mjs'
import { decisions, confusion, latency, summarize, compareReports } from './metrics.mjs'
import { makeReport, renderMarkdown } from './report.mjs'
import { fixturePaths } from './run.mjs'
import { verifyFrozenSources } from './scanners.mjs'

const root = fileURLToPath(new URL('../', import.meta.url))
const row = (overrides = {}) => ({
  id: 'X-1', split: 'tuning', kind: 'url', label: 'legitimate', scenario: 'ordinary-information',
  domains: ['reference.test'], input: 'https://reference.test/catalogue',
  provenance: { type: 'synthetic', method: 'scenario-author', source: 'unit test', rationale: 'Invented ordinary catalogue' },
  ...overrides,
})
const prediction = (id, label, score, extra = {}) => ({ id, label, score, status: score >= 80 ? 'Safe' : score > 50 ? 'Suspicious' : 'Dangerous', kind: 'url', split: 'tuning', latencyMs: 1, ...extra })
const cli = (args) => spawnSync(process.execPath, ['evaluation/run.mjs', ...args], { cwd: root, encoding: 'utf8' })

test('warning and block boundary decisions use safety score direction', () => {
  assert.deepEqual(decisions(80), { warning: false, block: false })
  assert.deepEqual(decisions(79.999), { warning: true, block: false })
  assert.deepEqual(decisions(50.001), { warning: true, block: false })
  assert.deepEqual(decisions(50), { warning: true, block: true })
  assert.deepEqual(decisions(0), { warning: true, block: true })
  assert.deepEqual(decisions(100), { warning: false, block: false })
  for (const bad of [-1, 101, NaN, Infinity, '50', null]) assert.throws(() => decisions(bad))
  for (const thresholds of [{ warningBelow: 50, blockAtMost: 50 }, { warningBelow: 101, blockAtMost: 0 }, { warningBelow: 80, blockAtMost: -1 }]) assert.throws(() => decisions(60, thresholds))
})

test('hand-calculated confusion counts, denominators and separate policies', () => {
  const rows = [prediction('p1', 'phishing', 20), prediction('p2', 'phishing', 60), prediction('p3', 'phishing', 90), prediction('n1', 'legitimate', 40), prediction('n2', 'legitimate', 70), prediction('n3', 'legitimate', 100)]
  assert.deepEqual(confusion(rows, 'warning'), { tp: 2, fp: 2, tn: 1, fn: 1, accuracy: 0.5, precision: 0.5, recall: 2 / 3, f1: 4 / 7, fpr: 2 / 3, falsePositiveIds: ['n1', 'n2'], falseNegativeIds: ['p3'] })
  assert.deepEqual(confusion(rows, 'block'), { tp: 1, fp: 1, tn: 2, fn: 2, accuracy: 0.5, precision: 0.5, recall: 1 / 3, f1: 2 / 5, fpr: 1 / 3, falsePositiveIds: ['n1'], falseNegativeIds: ['p2', 'p3'] })
  assert.equal(summarize(rows).overall.count, 6)
})

test('undefined ratios stay null for empty, no-positive and no-negative groups', () => {
  const empty = confusion([], 'warning')
  assert.equal(empty.precision, null)
  assert.equal(empty.recall, null)
  assert.equal(empty.fpr, null)
  assert.equal(empty.accuracy, null)
  assert.equal(empty.f1, null)
  const allNegative = confusion([prediction('a', 'legitimate', 100)], 'warning')
  assert.equal(allNegative.precision, null)
  assert.equal(allNegative.recall, null)
  assert.equal(allNegative.fpr, 0)
  const allPositive = confusion([prediction('a', 'phishing', 100)], 'warning')
  assert.equal(allPositive.recall, 0)
  assert.equal(allPositive.f1, 0)
  assert.equal(allPositive.fpr, null)
})

test('latency uses arithmetic mean and nearest-rank percentiles', () => {
  assert.deepEqual(latency([1, 2, 3, 4, 10].map((latencyMs) => ({ latencyMs }))), { count: 5, meanMs: 4, p50Ms: 3, p95Ms: 10, maxMs: 10 })
  assert.equal(latency([]).meanMs, null)
  assert.throws(() => latency([{ latencyMs: -1 }]))
})

test('fixtures have 60 valid balanced cases, disjoint scenarios and domain groups', () => {
  const rows = loadDatasets(fixturePaths)
  assert.equal(rows.length, 60)
  for (const split of ['tuning', 'held-out']) for (const kind of ['url', 'message', 'email']) for (const label of ['legitimate', 'phishing']) assert.equal(rows.filter((r) => r.split === split && r.kind === kind && r.label === label).length, 5)
  assert.ok(rows.every((r) => r.provenance.type === 'synthetic'))
})

test('reject invalid rows, labels, provenance and duplicate IDs', () => {
  assert.throws(() => validateRows([]))
  for (const change of [{ label: 'safe' }, { split: 'test' }, { kind: 'file' }, { input: '' }, { id: 'https://private.test/a' }, { unexpected: true }, { domains: null }, { provenance: { type: 'external-labeled', source: 'scanner', method: 'detector-score', rationale: 'not independent' } }, { provenance: { type: 'synthetic', method: 'scenario-author' } }, { kind: 'email', input: { sender: 'a@private.test' } }]) assert.throws(() => validateRows([row(change)]))
  assert.throws(() => validateRows([row(), row()]), /duplicate ID/)
})

test('accept independently labeled external schema without relabeling', () => {
  const external = row({ provenance: { type: 'external-labeled', method: 'independent-human', source: 'Blinded analyst sample', rationale: 'Adjudicated using independent incident evidence' } })
  assert.equal(validateRows([external])[0].label, 'legitimate')
})

test('domain separation covers sibling hosts, case, trailing dots, IDNA and conservative suffixes', () => {
  assert.equal(domainGroup('accounts.Reference.test.'), 'reference.test')
  assert.equal(domainGroup('shop.example.co.uk'), 'co.uk')
  assert.equal(domainGroup('bücher.test'), domainGroup('xn--bcher-kva.test'))
  for (const host of ['reference.test', 'login.reference.test', 'REFERENCE.TEST.']) {
    assert.throws(() => validateRows([row(), row({ id: 'X-2', split: 'held-out', scenario: 'distinct-scenario', input: `https://${host}/different`, domains: [host] })]), /domain group overlaps/)
  }
  assert.throws(() => validateRows([row(), row({ id: 'X-2', split: 'held-out', domains: ['elsewhere.test'], input: 'https://elsewhere.test/new' })]), /scenario overlaps/)
})

test('caller cannot hide URL, email, bare or nested redirect hosts with empty declarations', () => {
  for (const candidate of [row({ domains: [] }), row({ kind: 'message', input: 'Go to reference.test/catalogue', domains: [] }), row({ kind: 'email', input: { sender: 'a@reference.test', subject: 'Hello', body: 'See https://other.test/catalogue' }, domains: ['reference.test'] }), row({ input: 'https://reference.test/?next=https%3A%2F%2Fhidden.test%2Fx' })]) assert.throws(() => validateRows([candidate]), /every observable hostname/)
  assert.deepEqual(observedDomains(row({ input: 'https://trusted.test@reference.test/path' })), ['reference.test'])
})

test('dataset fingerprint is order independent and input/label sensitive', () => {
  const a = row(), b = row({ id: 'X-2', input: 'https://reference.test/other' })
  assert.equal(datasetHash([a, b]), datasetHash([b, a]))
  assert.notEqual(datasetHash([a]), datasetHash([{ ...a, label: 'phishing' }]))
  assert.notEqual(datasetHash([a]), datasetHash([{ ...a, input: 'https://reference.test/changed' }]))
})

test('reports whitelist predictions and omit input, domain, provenance and raw scanner explanations', () => {
  const item = row({ input: 'https://reference.test/SECRET_TOKEN' })
  const report = makeReport([item], [prediction(item.id, item.label, 40, { details: item.input, warningSigns: [item.input] })])
  const serialized = JSON.stringify(report) + renderMarkdown(report)
  assert.ok(!serialized.includes('reference.test'))
  assert.ok(!serialized.includes('SECRET_TOKEN'))
  assert.ok(serialized.includes(item.id))
  assert.ok(serialized.includes('Independent real-world evaluation is outstanding'))
})

test('comparison captures improvement and regression, refuses mismatched dataset or thresholds', () => {
  const rows = [row({ label: 'phishing' }), row({ id: 'X-2' })]
  const baseline = makeReport(rows, [prediction('X-1', 'phishing', 100), prediction('X-2', 'legitimate', 100)])
  const current = makeReport(rows, [prediction('X-1', 'phishing', 40), prediction('X-2', 'legitimate', 40)])
  const comparison = compareReports(baseline, current)
  assert.equal(comparison.delta.overall.warning.recall, 1)
  assert.equal(comparison.delta.overall.warning.fpr, 1)
  assert.equal(comparison.delta.overall.warning.precision, null)
  assert.equal(comparison.changed.length, 2)
  assert.throws(() => compareReports(baseline, { ...current, datasetHash: 'different' }))
  assert.throws(() => compareReports(baseline, { ...current, thresholds: { warningBelow: 90, blockAtMost: 50 } }))
  assert.throws(() => compareReports({ ...baseline, predictions: [baseline.predictions[0], baseline.predictions[0]] }, current))
})

test('frozen source and fixtures match recorded baseline; baseline is preserved', () => {
  verifyFrozenSources()
  const report = JSON.parse(readFileSync(new URL('./baseline/report.json', import.meta.url), 'utf8'))
  assert.equal(report.datasetHash, datasetHash(loadDatasets(fixturePaths)))
  // Historical artifact predates accuracy/F1; preserve its bytes and verify all
  // originally recorded fields against freshly recomputed predictions.
  const legacyMetrics = JSON.parse(JSON.stringify(summarize(report.predictions, report.thresholds), (key, value) => ['accuracy', 'f1'].includes(key) ? undefined : value))
  assert.deepEqual(report.metrics, legacyMetrics)
  const result = cli(['--scanner', 'baseline', '--split', 'all', '--baseline', 'evaluation/baseline/report.json'])
  assert.equal(result.status, 0, result.stderr)
  assert.ok(result.stdout.includes('0 cases changed score or status'))
})

test('CLI defaults to tuning, validates combined splits before filtering, and never overwrites outputs', () => {
  const dir = mkdtempSync(join(tmpdir(), 'phishing-eval-test-'))
  try {
    const dataset = join(dir, 'private.jsonl'), output = join(dir, 'report.json')
    writeFileSync(dataset, JSON.stringify(row()) + '\n')
    let result = cli(['--scanner', 'baseline', '--dataset', dataset, '--out', output])
    assert.equal(result.status, 0, result.stderr)
    assert.equal(JSON.parse(readFileSync(output, 'utf8')).selectedSplit, 'tuning')
    result = cli(['--scanner', 'baseline', '--dataset', dataset, '--out', output])
    assert.notEqual(result.status, 0)
    writeFileSync(dataset, [row(), row({ id: 'X-2', split: 'held-out', scenario: 'different' })].map(JSON.stringify).join('\n'))
    result = cli(['--scanner', 'baseline', '--dataset', dataset, '--split', 'tuning'])
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /domain group overlaps/)
    writeFileSync(dataset, '{"input":"https://secret.example/PRIVATE" invalid}\n')
    result = cli(['validate', '--dataset', dataset])
    assert.notEqual(result.status, 0)
    assert.ok(!result.stderr.includes('PRIVATE'))
    assert.ok(!result.stderr.includes('secret.example'))
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('offline guard blocks fetch, HTTP, HTTPS, raw sockets, DNS, subprocesses and workers', () => {
  // Separate process keeps the test harness and CLI tests usable.
  const source = `
    import assert from 'node:assert/strict';
    import { disableNetwork } from './evaluation/offline.mjs';
    disableNetwork();
    const http = await import('node:http'), https = await import('node:https');
    const net = await import('node:net'), dns = await import('node:dns');
    const cp = await import('node:child_process'), workers = await import('node:worker_threads');
    for (const operation of [() => fetch('https://example.test'), () => http.get('http://example.test'), () => https.request('https://example.test'), () => net.connect(443, 'example.test'), () => dns.lookup('example.test', () => {}), () => new dns.Resolver().resolve('example.test', () => {}), () => cp.spawn('node'), () => new workers.Worker('')]) assert.throws(operation, /Offline evaluation forbids/);
  `
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', source], { cwd: root, encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
})
