import { normalizeCategories, normalizeCoverage } from './scanPresentation.js'

// Preview links contain display data only; they never create history records.
export function readSearchPreview(href) {
  try {
    const url = new URL(href)
    if (url.searchParams.get('preview') !== '1' || url.hash.length > 64000) return null
    const preview = JSON.parse(new URLSearchParams(url.hash.slice(1)).get('preview'))
    if (!preview || typeof preview.target !== 'string' ||
        !['http:', 'https:'].includes(new URL(preview.target).protocol) ||
        !['Safe', 'Suspicious', 'Dangerous'].includes(preview.status) ||
        !Number.isFinite(preview.score) || preview.score < 0 || preview.score > 100) return null

    const strings = (value) => Array.isArray(value)
      ? value.filter((item) => typeof item === 'string').slice(0, 50)
      : []
    return {
      target: preview.target,
      status: preview.status,
      score: preview.score,
      summary: typeof preview.summary === 'string' ? preview.summary : '',
      warningSigns: strings(preview.warningSigns),
      recommendations: strings(preview.recommendations),
      ...(preview.coverage !== undefined ? { coverage: normalizeCoverage(preview.coverage) } : {}),
      ...(preview.categories !== undefined ? { categories: normalizeCategories(preview.categories) } : {}),
      ...(preview.categoryWarnings !== undefined ? { categoryWarnings: strings(preview.categoryWarnings) } : {}),
    }
  } catch {
    return null
  }
}
