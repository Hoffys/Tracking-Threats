/* global self, caches */
const OFFLINE_CACHE = 'tracking-threats-offline-v1'

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(OFFLINE_CACHE).then((cache) => cache.add('/offline.html')))
})

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys()
    await Promise.all(keys.filter((key) => key.startsWith('tracking-threats-offline-') && key !== OFFLINE_CACHE)
      .map((key) => caches.delete(key)))
    await self.clients.claim()
  })())
})

// Only a static offline page is cached. API responses and client data stay on the network.
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url)
  if (event.request.method !== 'GET' || event.request.mode !== 'navigate' ||
      url.origin !== self.location.origin || url.pathname === '/api' || url.pathname.startsWith('/api/')) return
  event.respondWith(fetch(event.request).catch(async () => {
    const cached = await caches.match('/offline.html', { cacheName: OFFLINE_CACHE })
    return cached || new Response('You are offline. Reconnect and reload Tracking Threats.', {
      status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    })
  }))
})
