import assert from 'node:assert/strict'
import test from 'node:test'
import { summarizeSandboxVerdicts } from './fileScanner.js'

test('sandbox verdict summary distinguishes malicious, suspicious and unavailable reports', () => {
  assert.deepEqual(summarizeSandboxVerdicts({}), { checked: false, found: false, malicious: 0, suspicious: 0, sandboxes: [], deduction: 0 })
  const result = summarizeSandboxVerdicts({
    one: { category: 'malicious', sandbox_name: 'Sandbox One' },
    two: { category: 'harmless', sandbox_name: 'Sandbox Two' },
  })
  assert.equal(result.checked, true)
  assert.equal(result.found, true)
  assert.equal(result.deduction, 70)
})
