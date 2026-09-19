import assert from 'node:assert/strict'
import test from 'node:test'
import { hasVirusTotalDetections, parseProviderFlag } from './threatIntel.js'

test('parseProviderFlag accepts explicit provider truth values', () => {
  for (const value of [true, 1, '1', 'true', 'TRUE', 'y', 'Y', 'yes']) {
    assert.equal(parseProviderFlag(value), true)
  }
})

test('parseProviderFlag rejects false-like and unknown values', () => {
  for (const value of [false, 0, null, undefined, '', '0', 'false', 'n', 'no']) {
    assert.equal(parseProviderFlag(value), false)
  }
})

test('VirusTotal requires an actual malicious or suspicious detection', () => {
  assert.equal(hasVirusTotalDetections({ harmless: 72, malicious: 0, suspicious: 0 }), false)
  assert.equal(hasVirusTotalDetections({ malicious: 1, suspicious: 0 }), true)
  assert.equal(hasVirusTotalDetections({ malicious: 0, suspicious: 2 }), true)
})
