import assert from 'node:assert/strict'
import test from 'node:test'
import { validateScanInput } from './scanInput.js'

const validate = (body, path = '/scan/url') => {
  let status = 200
  validateScanInput({ body, path }, { status(value) { status = value; return this }, json() {} }, () => {})
  return status
}

test('malformed scan types and unsupported URL schemes are rejected before scanning', () => {
  for (const body of [undefined, [], { url: {} }, { url: 'ftp://example.com/file' }, { url: ' ' }, { url: 'x'.repeat(9000) }]) {
    assert.equal(validate(body), 400)
  }
  assert.equal(validate({ message: {} }, '/scan/message'), 400)
  assert.equal(validate({ fileName: 'x.txt', size: -1 }, '/scan/file'), 400)
  assert.equal(validate({ body: 'x'.repeat(201 * 1024) }, '/scan/email'), 400)
  assert.equal(validate({ url: 'https://example.com/login' }), 200)
  assert.equal(validate({ url: 'example.com' }), 200)
})
