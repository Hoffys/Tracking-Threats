import net from 'node:net'
import { createRequire } from 'node:module'
import { getRiskFromScore, recommendationsFor } from './riskScorer.js'
import { providerCoverage } from './coverage.js'

const require = createRequire(import.meta.url)
const { authenticate } = require('mailauth')
const maxRawEmailLength = 400 * 1024
const timeoutMs = 7000

const resultOf = (value) => value?.status?.result ?? 'none'

export async function verifyEmailAuthentication({ rawEmail = '', smtpClientIp = '', smtpHelo = '', envelopeFrom = '' }, authenticateEmail = authenticate) {
  const raw = String(rawEmail ?? '')
  if (!raw.trim()) return {
    provider: 'Email authentication', checked: false, skipped: 'Raw RFC 822 message source was not supplied', found: false, deduction: 0,
    authentication: { dkim: 'not-checked', spf: 'not-checked', dmarc: 'not-checked' },
  }
  if (raw.length > maxRawEmailLength) throw new Error('Raw email source exceeds 400 KB')
  const ip = String(smtpClientIp ?? '').trim()
  if (ip && !net.isIP(ip)) throw new Error('SMTP client IP is invalid')
  const auth = await Promise.race([
    authenticateEmail(raw, {
      trustReceived: false,
      strict: true,
      rejectRsaSha1: true,
      disableArc: false,
      disableBimi: true,
      ...(ip ? { ip } : {}),
      ...(String(smtpHelo).trim() ? { helo: String(smtpHelo).trim().slice(0, 255) } : {}),
      ...(String(envelopeFrom).trim() ? { sender: String(envelopeFrom).trim().slice(0, 320) } : {}),
      mta: 'tracking-threats.local',
    }),
    new Promise((_, reject) => setTimeout(() => reject(new Error('Email authentication timed out')), timeoutMs)),
  ])
  const dkimResults = auth?.dkim?.results ?? []
  const dkim = dkimResults.some((item) => resultOf(item) === 'pass') ? 'pass'
    : dkimResults.some((item) => ['fail', 'policy', 'permerror'].includes(resultOf(item))) ? 'fail'
      : dkimResults.length ? resultOf(dkimResults[0]) : 'none'
  const spf = auth?.spf ? resultOf(auth.spf) : 'not-checked'
  const dmarc = auth?.dmarc ? resultOf(auth.dmarc) : 'not-checked'
  let deduction = 0
  const warnings = []
  if (dmarc === 'fail') { deduction += 40; warnings.push('DMARC authentication failed') }
  if (dkim === 'fail') { deduction += 25; warnings.push('DKIM signature verification failed') }
  if (spf === 'fail' || spf === 'softfail') { deduction += 18; warnings.push(`SPF authentication returned ${spf}`) }
  if (dmarc === 'pass' || dkim === 'pass' || spf === 'pass') deduction = Math.min(deduction, 45)
  return {
    provider: 'Email authentication', checked: true, found: deduction > 0, deduction: Math.min(deduction, 70),
    warning: warnings.join('; ') || null,
    authentication: {
      dkim, spf, dmarc,
      dkimDomains: dkimResults.map((item) => item.signingDomain).filter(Boolean).slice(0, 10),
      dmarcDomain: auth?.dmarc?.domain ?? null,
      dmarcPolicy: auth?.dmarc?.policy ?? null,
      transportMetadataSupplied: Boolean(ip && (envelopeFrom || smtpHelo)),
    },
  }
}

export async function enrichEmailAuthentication(input, baseAnalysis, verify = verifyEmailAuthentication) {
  let result
  try { result = await verify(input) } catch (error) {
    result = { provider: 'Email authentication', checked: false, error: String(error?.message ?? 'Email authentication failed').slice(0, 240), found: false, deduction: 0,
      authentication: { dkim: 'unavailable', spf: 'unavailable', dmarc: 'unavailable' } }
  }
  const providers = [...(baseAnalysis.details?.threatIntel ?? []), result]
  const score = Math.min(baseAnalysis.score, 100 - Number(result.deduction ?? 0))
  const risk = getRiskFromScore(score)
  const warningSigns = [...new Set([...baseAnalysis.warningSigns, ...(result.warning ? [result.warning] : [])])]
  const recommendations = recommendationsFor(risk.status)
  return {
    ...baseAnalysis, ...risk, score, warningSigns, recommendations, recommendation: recommendations.join(' '),
    details: {
      ...baseAnalysis.details,
      threatIntel: providers,
      emailAuthentication: result.authentication,
      coverage: providerCoverage(providers, [
        ...(baseAnalysis.details?.coverage?.limitations ?? []),
        result.checked ? 'DKIM was verified cryptographically. SPF requires the original SMTP client IP and envelope identity; DMARC uses authenticated identifier alignment.' : 'Email authentication requires the raw RFC 822 source; ordinary copied message text is not enough.',
      ]),
      ...(baseAnalysis.details?.emailBreakdown ? {
        emailBreakdown: {
          ...baseAnalysis.details.emailBreakdown,
          authentication: {
            score: 100 - Number(result.deduction ?? 0), status: getRiskFromScore(100 - Number(result.deduction ?? 0)).status,
            warningSigns: result.warning ? [result.warning] : [], authentication: result.authentication,
          },
        },
      } : {}),
    },
  }
}
