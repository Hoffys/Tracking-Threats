import { addWarning, getRiskFromScore, recommendationsFor, scoreWarnings } from './riskScorer.js'
import { scanMessage } from './messageScanner.js'

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

const getExtension = (fileName = '') => {
  const cleanName = fileName.toLowerCase().split(/[\\/]/).pop() ?? ''
  const parts = cleanName.split('.')
  return parts.length > 1 ? parts.at(-1) : ''
}

export function scanFile({ fileName = '', mimeType = '', size = 0, content = '' }) {
  const name = fileName.trim() || 'Unnamed file'
  const extension = getExtension(name)
  const text = String(content ?? '')
  const messageRisk = text ? scanMessage(text) : null
  const warnings = []

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
        textBytesScanned: text.length,
      },
    },
  }
}
