import { dbPromise } from '../db/database.js'

export const normalizeHost = (value = '') => value.toLowerCase().replace(/^www\./, '')

export const getHostFromTarget = (target = '') => {
  try {
    return normalizeHost(new URL(target.includes('://') ? target : `https://${target}`).hostname)
  } catch {
    return normalizeHost(String(target).split('/')[0] ?? '')
  }
}

export async function getMarkedSafeHosts() {
  const db = await dbPromise
  const rows = await db.all(`
    SELECT DISTINCT target
    FROM blocked_threats
    WHERE type = 'URL'
      AND review_status = 'marked_safe'
  `)

  return [...new Set(rows.map((row) => getHostFromTarget(row.target)).filter(Boolean))]
}

export async function isMarkedSafeUrlTarget(target) {
  const host = getHostFromTarget(target)
  if (!host) return false

  const safeHosts = await getMarkedSafeHosts()
  return safeHosts.some((safeHost) => host === safeHost || host.endsWith(`.${safeHost}`))
}
