import { addWarning, getRiskFromScore, recommendationsFor, scoreWarnings } from './riskScorer.js'
import { scanMessage } from './messageScanner.js'

const requestTimeoutMs = 4500

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

const withTimeout = async (url, options) => {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), requestTimeoutMs)

  try {
    return await fetch(url, { ...options, signal: controller.signal })
  } finally {
    clearTimeout(timeout)
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
  if (!apiKey || !sha256Pattern.test(sha256 ?? '')) return null

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
      checked: true,
      found: false,
      warning: null,
      deduction: 0,
    }
  }

  if (!response.ok) throw new Error(`VirusTotal file lookup returned ${response.status}`)

  const payload = await response.json()
  const stats = payload?.data?.attributes?.last_analysis_stats ?? {}
  const malicious = Number(stats.malicious ?? 0)
  const suspicious = Number(stats.suspicious ?? 0)

  return {
    provider: 'VirusTotal File',
    checked: true,
    found: true,
    sha256,
    stats,
    warning:
      malicious > 0
        ? `VirusTotal reports ${malicious} malicious engine detection${malicious === 1 ? '' : 's'} for this file hash`
        : suspicious > 0
          ? `VirusTotal reports ${suspicious} suspicious engine detection${suspicious === 1 ? '' : 's'} for this file hash`
          : null,
    deduction: malicious > 0 ? 65 : suspicious > 0 ? 30 : 0,
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
  } else if (sha256) {
    try {
      const result = await checkVirusTotalFileHash(sha256)
      if (result) threatIntel.push(result)
    } catch (error) {
      threatIntel.push({
        provider: 'VirusTotal File',
        checked: true,
        error: formatProviderError(error),
      })
    }
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
    },
  }
}
