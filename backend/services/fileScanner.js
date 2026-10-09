import { addWarning, getRiskFromScore, recommendationsFor, scoreWarnings } from './riskScorer.js'
import { scanMessage } from './messageScanner.js'
import { hasVirusTotalDetections } from './threatIntel.js'
import { providerRequest } from './providerRequest.js'
import { providerCoverage } from './coverage.js'


const dangerousExtensions = new Set([
  'bat',
  'cmd',
  'com',
  'exe',
  'hta',
  'js',
  'jse',
  'msi',
  'ps1',
  'scr',
  'vbe',
  'vbs',
  'wsf',
])

const macroEnabledExtensions = new Set(['docm', 'xlsm', 'pptm'])
const doubleExtensionPattern = /\.(pdf|docx?|xlsx?|pptx?|txt|jpg|png)\.(exe|scr|bat|cmd|js|vbs|ps1)$/i
const sha256Pattern = /^[a-f0-9]{64}$/i

const withTimeout = providerRequest
const boundedProviderText = (value, limit = 120) =>
  (typeof value === 'string' ? value.replace(/\s+/g, ' ').trim().slice(0, limit) : '')

export function summarizeSandboxVerdicts(verdicts = {}) {
  const entries = Object.values(verdicts ?? {}).filter((item) => item && typeof item === 'object')
  const malicious = entries.filter((item) => item.category === 'malicious')
  const suspicious = entries.filter((item) => item.category === 'suspicious')
  return {
    checked: entries.length > 0,
    found: malicious.length > 0 || suspicious.length > 0,
    malicious: malicious.length,
    suspicious: suspicious.length,
    sandboxes: entries.map((item) => item.sandbox_name).filter(Boolean).slice(0, 20),
    deduction: malicious.length > 0 ? 70 : suspicious.length > 0 ? 35 : 0,
  }
}

const formatProviderError = (error) => {
  const code = error?.cause?.code ?? error?.code
  const message = error?.cause?.message ?? error?.message ?? 'File reputation lookup failed'

  if (code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
    return 'TLS certificate verification failed; restart the backend with Node system CA support'
  }

  if (error?.name === 'AbortError') {
    return 'Lookup timed out'
  }

  return code ? `${message} (${code})` : message
}

const getExtension = (fileName = '') => {
  const cleanName = fileName.toLowerCase().split(/[\\/]/).pop() ?? ''
  const parts = cleanName.split('.')
  return parts.length > 1 ? parts.at(-1) : ''
}

async function checkVirusTotalFileHash(sha256) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY
  if (process.env.REPUTATION_ENABLED === 'false' || !apiKey || !sha256Pattern.test(sha256 ?? '')) return null

  const response = await withTimeout(
    `https://www.virustotal.com/api/v3/files/${encodeURIComponent(sha256)}`,
    {
      headers: {
        accept: 'application/json',
        'x-apikey': apiKey,
      },
    },
  )

  if (response.status === 404) {
    return {
      provider: 'VirusTotal File',
      checked: false,
      skipped: 'File hash is not in the provider database',
      found: false,
      warning: null,
      deduction: 0,
    }
  }

  if (!response.ok) throw new Error(`VirusTotal file lookup returned ${response.status}`)

  const payload = await response.json()
  const attributes = payload?.data?.attributes ?? {}
  const stats = attributes.last_analysis_stats ?? {}
  const sandbox = summarizeSandboxVerdicts(attributes.sandbox_verdicts)
  const malicious = Number(stats.malicious ?? 0)
  const suspicious = Number(stats.suspicious ?? 0)

  return {
    provider: 'VirusTotal File',
    checked: true,
    found: hasVirusTotalDetections(stats) || sandbox.found,
    sha256,
    stats,
    warning:
      sandbox.malicious > 0
        ? `${sandbox.malicious} VirusTotal sandbox${sandbox.malicious === 1 ? '' : 'es'} classified this file as malicious`
        : sandbox.suspicious > 0
          ? `${sandbox.suspicious} VirusTotal sandbox${sandbox.suspicious === 1 ? '' : 'es'} classified this file as suspicious`
          : malicious > 0
        ? `VirusTotal reports ${malicious} malicious engine detection${malicious === 1 ? '' : 's'} for this file hash`
        : suspicious > 0
          ? `VirusTotal reports ${suspicious} suspicious engine detection${suspicious === 1 ? '' : 's'} for this file hash`
          : null,
    deduction: Math.max(sandbox.deduction, malicious > 0 ? 65 : suspicious > 0 ? 30 : 0),
    sandbox,
  }
}

async function checkMalwareBazaarFileHash(sha256) {
  const authKey = process.env.MALWAREBAZAAR_AUTH_KEY
  if (process.env.REPUTATION_ENABLED === 'false' || !authKey || !sha256Pattern.test(sha256 ?? '')) return null

  const response = await withTimeout(
    'https://mb-api.abuse.ch/api/v1/',
    {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'Auth-Key': authKey,
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'TrackingThreats/1.0',
      },
      body: new URLSearchParams({ query: 'get_info', hash: sha256 }),
    },
  )

  if (!response.ok) throw new Error(`MalwareBazaar file lookup returned ${response.status}`)

  const payload = await response.json()
  if (payload?.query_status === 'hash_not_found') {
    return {
      provider: 'MalwareBazaar',
      checked: false,
      skipped: 'File hash is not in the provider database',
      found: false,
      warning: null,
      deduction: 0,
    }
  }

  if (payload?.query_status !== 'ok' || !Array.isArray(payload.data) || payload.data.length === 0) {
    throw new Error(`MalwareBazaar lookup returned ${payload?.query_status || 'an invalid response'}`)
  }

  const sample = payload.data[0] ?? {}
  const signature = boundedProviderText(sample.signature)
  const tags = Array.isArray(sample.tags)
    ? sample.tags.map((tag) => boundedProviderText(tag, 40)).filter(Boolean).slice(0, 20)
    : []
  const description = signature || tags.slice(0, 3).join(', ') || 'a known malware sample'

  return {
    provider: 'MalwareBazaar',
    checked: true,
    found: true,
    sha256,
    signature: signature || null,
    tags,
    fileType: boundedProviderText(sample.file_type, 40) || null,
    firstSeen: boundedProviderText(sample.first_seen, 40) || null,
    lastSeen: boundedProviderText(sample.last_seen, 40) || null,
    warning: `MalwareBazaar lists this file hash as ${description}`,
    deduction: 70,
  }
}

async function checkMetaDefenderFileHash(sha256) {
  const apiKey = process.env.METADEFENDER_API_KEY
  if (process.env.REPUTATION_ENABLED === 'false' || !apiKey || !sha256Pattern.test(sha256 ?? '')) return null

  const response = await withTimeout(
    `https://api.metadefender.com/v4/hash/${encodeURIComponent(sha256)}`,
    {
      headers: {
        accept: 'application/json',
        apikey: apiKey,
        'User-Agent': 'TrackingThreats/1.0',
      },
    },
  )

  if (response.status === 404) {
    return {
      provider: 'MetaDefender Cloud',
      checked: false,
      skipped: 'File hash is not in the provider database',
      found: false,
      warning: null,
      deduction: 0,
    }
  }

  if (!response.ok) throw new Error(`MetaDefender file lookup returned ${response.status}`)

  const payload = await response.json()
  const scanResults = payload?.scan_results
  const totalEngines = Math.max(0, Number(scanResults?.total_avs ?? 0))
  const detectedEngines = Math.max(0, Number(scanResults?.total_detected_avs ?? 0))
  const resultCode = Number(scanResults?.scan_all_result_i)

  if (!scanResults || totalEngines === 0 || !Number.isFinite(resultCode)) {
    return {
      provider: 'MetaDefender Cloud',
      checked: false,
      skipped: 'File hash has no completed multi-engine scan result',
      found: false,
      warning: null,
      deduction: 0,
    }
  }

  const suspicious = resultCode === 2
  const malicious = resultCode === 1 || detectedEngines > 0

  return {
    provider: 'MetaDefender Cloud',
    checked: true,
    found: malicious || suspicious,
    sha256,
    resultCode,
    detectedEngines,
    totalEngines,
    warning: malicious
      ? `MetaDefender reports ${detectedEngines} of ${totalEngines} anti-malware engines detected this file hash`
      : suspicious
        ? `MetaDefender classified this file hash as suspicious across ${totalEngines} anti-malware engines`
        : null,
    deduction: malicious ? 65 : suspicious ? 30 : 0,
  }
}

async function resolveFileReputation(provider, sha256, lookup) {
  try {
    const result = await lookup(sha256)
    return result ?? {
      provider,
      checked: false,
      found: false,
      skipped: 'File reputation is not configured',
    }
  } catch (error) {
    return {
      provider,
      checked: true,
      error: formatProviderError(error),
    }
  }
}

export async function scanFile({ fileName = '', mimeType = '', size = 0, content = '', sha256 = '' }) {
  const name = fileName.trim() || 'Unnamed file'
  const extension = getExtension(name)
  const text = String(content ?? '')
  const messageRisk = text ? scanMessage(text) : null
  const warnings = []
  const threatIntel = []

  if (sha256 && !sha256Pattern.test(sha256)) {
    threatIntel.push({
      provider: 'VirusTotal File',
      checked: false,
      error: 'Invalid SHA-256 hash',
    })
    threatIntel.push({
      provider: 'MalwareBazaar',
      checked: false,
      error: 'Invalid SHA-256 hash',
    })
    threatIntel.push({
      provider: 'MetaDefender Cloud',
      checked: false,
      error: 'Invalid SHA-256 hash',
    })
  } else if (sha256) {
    threatIntel.push(...await Promise.all([
      resolveFileReputation('VirusTotal File', sha256, checkVirusTotalFileHash),
      resolveFileReputation('MalwareBazaar', sha256, checkMalwareBazaarFileHash),
      resolveFileReputation('MetaDefender Cloud', sha256, checkMetaDefenderFileHash),
    ]))
  } else {
    threatIntel.push(
      { provider: 'VirusTotal File', checked: false, found: false, skipped: 'No file hash was supplied' },
      { provider: 'MalwareBazaar', checked: false, found: false, skipped: 'No file hash was supplied' },
      { provider: 'MetaDefender Cloud', checked: false, found: false, skipped: 'No file hash was supplied' },
    )
  }

  addWarning(warnings, !extension, 'File has no visible extension', 12)
  addWarning(warnings, dangerousExtensions.has(extension), `File uses executable .${extension} extension`, 34)
  addWarning(warnings, macroEnabledExtensions.has(extension), `File uses macro-enabled .${extension} extension`, 24)
  addWarning(warnings, doubleExtensionPattern.test(name), 'File name uses a misleading double extension', 28)
  addWarning(warnings, size > 15 * 1024 * 1024, 'File is unusually large for quick local inspection', 8)
  addWarning(
    warnings,
    /autoopen|document_open|wscript\.shell|powershell|invoke-webrequest|downloadstring|cmd\.exe/i.test(text),
    'File content contains macro or script execution indicators',
    30,
  )
  addWarning(
    warnings,
    /password|credentials|verify account|login|payment|bank/i.test(name),
    'File name contains credential or payment-related wording',
    12,
  )
  addWarning(
    warnings,
    messageRisk?.status === 'Suspicious',
    'File text content contains suspicious phishing language',
    14,
  )
  addWarning(
    warnings,
    messageRisk?.status === 'Dangerous',
    'File text content contains dangerous phishing indicators',
    24,
  )
  for (const result of threatIntel) {
    addWarning(warnings, Boolean(result.warning), result.warning, result.deduction ?? 0)
  }

  const score = scoreWarnings(warnings)
  const risk = getRiskFromScore(score)
  const recommendations = recommendationsFor(risk.status)

  return {
    ...risk,
    score,
    summary:
      warnings.length > 0
        ? `Found ${warnings.length} file warning sign${warnings.length === 1 ? '' : 's'}.`
        : 'No strong file threat indicators were found.',
    warningSigns: warnings.map((warning) => warning.label),
    recommendations,
    recommendation: recommendations.join(' '),
    details: {
      file: {
        fileName: name,
        mimeType,
        size,
        extension: extension || 'none',
        sha256: sha256 || null,
        textBytesScanned: text.length,
      },
      threatIntel,
      coverage: providerCoverage(threatIntel, [
        'File metadata and limited text were checked. When available, VirusTotal verdicts, MalwareBazaar listings, and MetaDefender multi-engine results for the supplied hash were used; unknown files are not uploaded or executed by Tracking Threats.',
      ]),
      categories: warnings.length ? ['file-risk'] : [],
    },
  }
}
