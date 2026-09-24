import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'

const source = readFileSync(new URL('../../public/sw.js', import.meta.url), 'utf8')
function worker(fetch) {
  const handlers = {}
  const fallback = new Response('Offline instructions')
  const context = {
    URL, Response, fetch,
    self: { location: { origin: 'https://app.example' }, addEventListener: (type, fn) => { handlers[type] = fn } },
    caches: { match: async () => fallback },
  }
  vm.runInNewContext(source, context)
  const request = (path, mode = 'navigate', method = 'GET') => {
    let response
    handlers.fetch({ request: { url: new URL(path, context.self.location.origin).href, mode, method }, respondWith: (value) => { response = value } })
    return response
  }
  return { request, fallback }
}

test('PWA uses offline instructions for failed page navigation', async () => {
  const { request, fallback } = worker(async () => { throw new Error('Offline') })
  assert.equal(await request('/?page=history'), fallback)
})

test('PWA never intercepts API, external, asset or write requests', () => {
  const { request } = worker(() => { throw new Error('Must not fetch') })
  assert.equal(request('/api/health'), undefined)
  assert.equal(request('/api'), undefined)
  assert.equal(request('/api/scan/url', 'cors', 'POST'), undefined)
  assert.equal(request('https://other.example/'), undefined)
  assert.equal(request('/assets/app.js', 'cors'), undefined)
})

test('PWA returns fresh online pages instead of a cached application', async () => {
  const latest = new Response('Latest version')
  const { request } = worker(async () => latest)
  assert.equal(await request('/'), latest)
})
