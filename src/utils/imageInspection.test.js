import assert from 'node:assert/strict'
import test from 'node:test'
import { extractImageIndicators } from './imageInspection.js'

test('image indicators combine bounded OCR and unique QR values for scanning', () => {
  const result = extractImageIndicators('Verify account and enter OTP', ['https://example.test/login', 'https://example.test/login'])
  assert.equal(result.qr.length, 1)
  assert.match(result.scanText, /enter OTP/)
  assert.match(result.scanText, /https:\/\/example\.test\/login/)
})
