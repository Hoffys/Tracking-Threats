import dns from 'node:dns/promises'
import https from 'node:https'
import net from 'node:net'
import { getRiskFromScore, recommendationsFor } from './riskScorer.js'
import { providerCoverage } from './coverage.js'

const maxRedirects = 3
const maxPageBytes = 512 * 1024
const timeoutMs = 4500

const decodeEntities = (value = '') => String(value)
  .replaceAll('&amp;', '&').replaceAll('&quot;', '"').replaceAll('&#39;', "'")
  .replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim()

function isPublicIpv4(address) {
  const octets = address.split('.').map(Number)
  if (octets.length !== 4 || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return false
  const [a, b, c] = octets
  return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 0 || (b === 168))) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113))
}

export function isPublicAddress(address) {
  const normalized = String(address ?? '').toLowerCase().split('%')[0]
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)?.[1]
  if (mapped) return isPublicIpv4(mapped)
  if (net.isIP(normalized) === 4) return isPublicIpv4(normalized)
  if (net.isIP(normalized) !== 6) return false
  return !(normalized === '::' || normalized === '::1' || normalized.startsWith('fc') ||
    normalized.startsWith('fd') || /^fe[89ab]/.test(normalized) || normalized.startsWith('ff') ||
    normalized.startsWith('2001:db8:'))
}

async function approvedAddresses(hostname) {
  if (net.isIP(hostname)) {
    if (!isPublicAddress(hostname)) throw Object.assign(new Error('Private or reserved destinations are not inspected'), { code: 'PRIVATE_DESTINATION' })
    return [{ address: hostname, family: net.isIP(hostname) }]
  }
  const addresses = await dns.lookup(hostname, { all: true, verbatim: true })
  if (addresses.length === 0 || addresses.some(({ address }) => !isPublicAddress(address))) {
    throw Object.assign(new Error('Destination resolved to a private or reserved address'), { code: 'PRIVATE_DESTINATION' })
  }
  return addresses
}

async function requestPage(url) {
  const parsed = new URL(url)
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.port) {
    throw Object.assign(new Error('Page inspection requires a standard HTTPS URL without credentials'), { code: 'UNSUPPORTED_DESTINATION' })
  }
  const addresses = await approvedAddresses(parsed.hostname)
  const pinned = addresses[0]
  return new Promise((resolve, reject) => {
    const request = https.request({
      protocol: 'https:', hostname: parsed.hostname, servername: parsed.hostname, port: 443,
      path: `${parsed.pathname}${parsed.search}`, method: 'GET', timeout: timeoutMs,
      headers: { accept: 'text/html,application/xhtml+xml;q=0.9', 'user-agent': 'Tracking-Threats-Page-Inspector/1.0' },
      lookup: (_hostname, options, callback) => {
        const result = options?.all ? [pinned] : pinned.address
        callback(null, result, pinned.family)
      },
    }, (response) => {
      const chunks = []
      let length = 0
      response.on('data', (chunk) => {
        length += chunk.length
        if (length > maxPageBytes) {
          request.destroy(Object.assign(new Error('Page response exceeded 512 KB'), { code: 'PAGE_TOO_LARGE' }))
          return
        }
        chunks.push(chunk)
      })
      response.on('end', () => resolve({
        status: response.statusCode ?? 0,
        headers: response.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }))
    })
    request.once('timeout', () => request.destroy(Object.assign(new Error('Page inspection timed out'), { code: 'PAGE_TIMEOUT' })))
    request.once('error', reject)
    request.end()
  })
}

export function inspectHtml(html, pageUrl) {
  const text = String(html ?? '').slice(0, maxPageBytes)
  const page = new URL(pageUrl)
  const title = decodeEntities(text.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] ?? '').slice(0, 200)
  const visibleText = decodeEntities(text.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ')).slice(0, 20000)
  const passwordFields = (text.match(/<input\b[^>]*type\s*=\s*["']?password\b[^>]*>/gi) ?? []).length
  const forms = [...text.matchAll(/<form\b([^>]*)>/gi)].slice(0, 20)
  let externalFormActions = 0
  for (const match of forms) {
    const action = match[1].match(/\baction\s*=\s*["']([^"']+)["']/i)?.[1]
    if (!action) continue
    try {
      const destination = new URL(action, page)
      if (destination.hostname !== page.hostname) externalFormActions += 1
    } catch { externalFormActions += 1 }
  }
  const metaTarget = text.match(/<meta\b[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*url\s*=\s*([^"';\s>]+)/i)?.[1]
  let externalMetaRefresh = false
  if (metaTarget) {
    try { externalMetaRefresh = new URL(metaTarget, page).hostname !== page.hostname } catch { externalMetaRefresh = true }
  }
  const credentialLanguage = /\b(sign[ -]?in|log[ -]?in|verify|password|passcode|one[ -]?time|otp|credit card|bank account)\b/i.test(`${title} ${visibleText}`)
  const hiddenFrames = (text.match(/<(?:iframe|form)\b[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^>]*>/gi) ?? []).length
  const obfuscatedScripts = /(?:eval\s*\(|atob\s*\(|fromCharCode\s*\(|document\.write\s*\()/i.test(text)
  const findings = []
  if (passwordFields > 0 && externalFormActions > 0) findings.push({ label: 'Password form submits to a different host', deduction: 50 })
  else if (passwordFields > 0 && credentialLanguage) findings.push({ label: 'Page contains a credential-entry form', deduction: 18 })
  if (externalMetaRefresh) findings.push({ label: 'Page redirects through an external meta-refresh target', deduction: 15 })
  if (hiddenFrames > 0 && credentialLanguage) findings.push({ label: 'Credential-themed page contains hidden forms or frames', deduction: 15 })
  if (obfuscatedScripts && credentialLanguage) findings.push({ label: 'Credential-themed page contains obfuscated script patterns', deduction: 12 })
  return {
    title, passwordFields, formCount: forms.length, externalFormActions, externalMetaRefresh,
    hiddenFrames, obfuscatedScripts, findings,
  }
}

export async function inspectPage(target, requester = requestPage) {
  if (process.env.REPUTATION_ENABLED === 'false' || process.env.PAGE_INSPECTION_ENABLED === 'false') {
    return { provider: 'Page inspection', checked: false, skipped: 'Page inspection is disabled', found: false, deduction: 0 }
  }
  let current = new URL(target.includes('://') ? target : `https://${target}`)
  const redirects = []
  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    const response = await requester(current.href)
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.location
      if (!location || hop === maxRedirects) throw Object.assign(new Error('Redirect limit reached'), { code: 'REDIRECT_LIMIT' })
      const next = new URL(location, current)
      if (next.protocol !== 'https:') throw Object.assign(new Error('Redirect left HTTPS'), { code: 'UNSAFE_REDIRECT' })
      redirects.push({ from: current.origin, to: next.origin })
      current = next
      continue
    }
    const contentType = String(response.headers['content-type'] ?? '')
    if (response.status < 200 || response.status >= 300) throw new Error(`Page returned HTTP ${response.status}`)
    if (!/text\/html|application\/xhtml\+xml/i.test(contentType)) {
      return { provider: 'Page inspection', checked: false, skipped: `Unsupported page content type: ${contentType || 'unknown'}`, found: false, deduction: 0, redirects }
    }
    const inspection = inspectHtml(response.body, current.href)
    const deduction = Math.min(70, inspection.findings.reduce((sum, item) => sum + item.deduction, 0))
    return {
      provider: 'Page inspection', checked: true, found: deduction > 0, deduction,
      warning: inspection.findings.map((item) => item.label).join('; ') || null,
      redirects, finalOrigin: current.origin, inspection,
    }
  }
  throw new Error('Page inspection could not complete')
}

export function pageSnapshotResult(snapshot = {}) {
  const passwordFields = Math.min(100, Number(snapshot.passwordFields ?? 0) || 0)
  const externalFormActions = Math.min(100, Number(snapshot.externalFormActions ?? 0) || 0)
  const hiddenFrames = Math.min(100, Number(snapshot.hiddenFrames ?? 0) || 0)
  const credentialLanguage = snapshot.credentialLanguage === true
  const obfuscatedScripts = snapshot.obfuscatedScripts === true
  const findings = []
  if (passwordFields > 0 && externalFormActions > 0) findings.push({ label: 'Rendered password form submits to a different host', deduction: 50 })
  else if (passwordFields > 0 && credentialLanguage) findings.push({ label: 'Rendered page contains a credential-entry form', deduction: 18 })
  if (hiddenFrames > 0 && credentialLanguage) findings.push({ label: 'Rendered credential page contains hidden forms or frames', deduction: 15 })
  if (obfuscatedScripts && credentialLanguage) findings.push({ label: 'Rendered credential page contains obfuscated scripts', deduction: 12 })
  const redirects = Array.isArray(snapshot.redirectChain) ? snapshot.redirectChain.slice(-5).filter((item) => typeof item === 'string').map((item) => {
    try { return new URL(item).origin } catch { return null }
  }).filter(Boolean) : []
  const deduction = Math.min(70, findings.reduce((sum, item) => sum + item.deduction, 0))
  return {
    provider: 'Rendered page inspection', checked: true, found: deduction > 0, deduction,
    warning: findings.map((item) => item.label).join('; ') || null,
    inspection: { passwordFields, externalFormActions, hiddenFrames, credentialLanguage, obfuscatedScripts,
      formCount: Math.min(100, Number(snapshot.formCount ?? 0) || 0), title: String(snapshot.title ?? '').slice(0, 200), findings },
    redirects,
  }
}

export async function enrichPageSnapshot(snapshot, baseAnalysis) {
  if (!snapshot) return baseAnalysis
  const rendered = pageSnapshotResult(snapshot)
  return enrichPageInspection('', baseAnalysis, async () => rendered)
}

export async function enrichPageInspection(target, baseAnalysis, inspect = inspectPage) {
  let result
  try { result = await inspect(target) } catch (error) {
    result = { provider: 'Page inspection', checked: false, error: String(error?.message ?? 'Page inspection failed').slice(0, 240), found: false, deduction: 0 }
  }
  const providers = [...(baseAnalysis.details?.threatIntel ?? []), result]
  const pageScore = 100 - Number(result.deduction ?? 0)
  const score = Math.min(baseAnalysis.score, pageScore)
  const risk = getRiskFromScore(score)
  const warningSigns = [...new Set([...baseAnalysis.warningSigns, ...(result.warning ? [result.warning] : [])])]
  const recommendations = recommendationsFor(risk.status, baseAnalysis.details?.categories)
  return {
    ...baseAnalysis, ...risk, score, warningSigns, recommendations,
    recommendation: recommendations.join(' '),
    summary: warningSigns.length ? `Found ${warningSigns.length} warning sign${warningSigns.length === 1 ? '' : 's'} after URL, reputation, redirect, and page checks.` : 'No strong indicators were found in URL, reputation, redirect, and page checks.',
    details: {
      ...baseAnalysis.details,
      threatIntel: providers,
      pageInspection: result.inspection ? { ...result.inspection, findings: result.inspection.findings.map((item) => item.label), redirects: result.redirects, finalOrigin: result.finalOrigin } : null,
      coverage: providerCoverage(providers, ['Static HTML inspection only; client-rendered behavior is checked separately by the browser extension when the user requests it.']),
    },
  }
}
