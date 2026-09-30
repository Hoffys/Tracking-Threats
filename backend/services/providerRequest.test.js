import assert from 'node:assert/strict'
import http from 'node:http'
import test from 'node:test'
import { providerRequest } from './providerRequest.js'

test('provider timeout covers a stalled body after headers arrive', async (t) => {
  const server = http.createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' })
    response.write('{')
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => { server.closeAllConnections(); server.close() })
  await assert.rejects(providerRequest(`http://127.0.0.1:${server.address().port}`, {}, { timeoutMs: 100 }), { name: 'AbortError' })
})

test('provider responses are size-bounded', async (t) => {
  const server = http.createServer((_request, response) => response.end('x'.repeat(1000)))
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => { server.closeAllConnections(); server.close() })
  await assert.rejects(providerRequest(`http://127.0.0.1:${server.address().port}`, {}, { maxBytes: 100 }), /size limit/)
})
