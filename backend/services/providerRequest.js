// Keep the timeout active through the body, not just until response headers.
export async function providerRequest(url, options = {}, { timeoutMs = 4500, maxBytes = 1024 * 1024 } = {}) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const response = await fetch(url, { ...options, signal: controller.signal })
    const reader = response.body?.getReader()
    const chunks = []
    let bytes = 0
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        bytes += value.byteLength
        if (bytes > maxBytes) {
          await reader.cancel()
          throw new Error('Reputation response exceeded the size limit')
        }
        chunks.push(value)
      }
    }
    return new Response(bytes ? Buffer.concat(chunks) : null, {
      status: response.status, statusText: response.statusText, headers: response.headers,
    })
  } finally {
    clearTimeout(timer)
  }
}
