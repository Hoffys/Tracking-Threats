export const maxFileTextPreviewBytes = 64 * 1024

const textMimeTypes = new Set([
  'application/csv',
  'application/javascript',
  'application/json',
  'application/ld+json',
  'application/sql',
  'application/x-httpd-php',
  'application/x-javascript',
  'application/x-powershell',
  'application/x-sh',
  'application/xhtml+xml',
  'application/xml',
  'application/yaml',
  'image/svg+xml',
])

const textExtensions = new Set([
  'bat', 'c', 'cfg', 'cmd', 'conf', 'cpp', 'cs', 'css', 'csv', 'go', 'h', 'hpp',
  'htm', 'html', 'ini', 'java', 'js', 'json', 'jsx', 'log', 'md', 'mjs', 'php',
  'ps1', 'py', 'rb', 'rs', 'sh', 'sql', 'svg', 'text', 'toml', 'ts', 'tsx', 'txt',
  'vbs', 'xml', 'yaml', 'yml',
])

const getExtension = (name = '') => {
  const match = String(name).toLowerCase().match(/\.([a-z0-9]+)$/)
  return match?.[1] ?? ''
}

export function canInspectFileAsText(file) {
  const mimeType = String(file?.type ?? '').toLowerCase().split(';', 1)[0].trim()
  return mimeType.startsWith('text/') || textMimeTypes.has(mimeType) || textExtensions.has(getExtension(file?.name))
}

export async function readFileTextPreview(file) {
  if (!canInspectFileAsText(file)) return ''
  return file.slice(0, maxFileTextPreviewBytes).text()
}
