import { isIP } from 'node:net'

export const URL_MODEL_DIMENSION = 2048

function hashFeature(value, dimension) {
  let hash = 2166136261
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index)
    hash = Math.imul(hash, 16777619)
  }
  return (hash >>> 0) % dimension
}

function bucket(value, size, maximum) {
  return Math.min(maximum, Math.floor(value / size))
}

export function urlLexicalFeatures(input, dimension = URL_MODEL_DIMENSION) {
  const raw = String(input ?? '').trim().slice(0, 8192)
  let url
  try { url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`) } catch { return [] }
  if (!['http:', 'https:'].includes(url.protocol)) return []

  const host = url.hostname.toLowerCase().replace(/\.$/, '')
  const path = `${url.pathname}${url.search}`.toLowerCase().slice(0, 2048)
  const normalized = `${url.protocol}//${host}${path}`
  const digits = (normalized.match(/\d/g) ?? []).length
  const punctuation = (normalized.match(/[-_.~%=&@]/g) ?? []).length
  const labels = host.split('.').filter(Boolean)
  const features = new Set([
    `scheme:${url.protocol}`,
    `url-length:${bucket(normalized.length, 10, 40)}`,
    `host-length:${bucket(host.length, 5, 30)}`,
    `path-length:${bucket(path.length, 10, 30)}`,
    `digit-ratio:${bucket((digits * 20) / Math.max(1, normalized.length), 1, 20)}`,
    `punctuation-ratio:${bucket((punctuation * 20) / Math.max(1, normalized.length), 1, 20)}`,
    `labels:${Math.min(10, labels.length)}`,
    `hyphens:${Math.min(10, (host.match(/-/g) ?? []).length)}`,
    `query:${url.search ? 1 : 0}`,
    `userinfo:${url.username || url.password ? 1 : 0}`,
    `ip:${isIP(host.replace(/^\[|\]$/g, '')) ? 1 : 0}`,
    `punycode:${host.includes('xn--') ? 1 : 0}`,
    `tld:${labels.at(-1) ?? ''}`,
  ])

  const addNgrams = (prefix, value, minimum, maximum) => {
    const bounded = `^${value.slice(0, 512)}$`
    for (let size = minimum; size <= maximum; size += 1) {
      for (let index = 0; index <= bounded.length - size; index += 1) {
        features.add(`${prefix}${size}:${bounded.slice(index, index + size)}`)
      }
    }
  }
  addNgrams('h', host, 3, 5)
  addNgrams('p', path, 3, 4)
  return [...new Set([...features].map((feature) => hashFeature(feature, dimension)))].sort((a, b) => a - b)
}

export function lexicalProbability(input, model) {
  const indices = urlLexicalFeatures(input, model.dimension)
  if (!indices.length) return 0
  const scale = 1 / Math.sqrt(indices.length)
  let logit = model.bias
  for (const index of indices) logit += model.weights[index] * scale
  if (logit >= 35) return 1
  if (logit <= -35) return 0
  return 1 / (1 + Math.exp(-logit))
}
