export const announcementTypes = new Set(['update', 'security', 'maintenance', 'general'])
export const announcementPriorities = new Set(['normal', 'important', 'critical'])
export const extensionVersionPattern = /^\d{1,5}\.\d{1,5}\.\d{1,5}(\.\d{1,5})?$/

export function compareExtensionVersions(left, right) {
  const leftParts = String(left ?? '').split('.').map(Number)
  const rightParts = String(right ?? '').split('.').map(Number)
  const length = Math.max(leftParts.length, rightParts.length)
  for (let index = 0; index < length; index += 1) {
    const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0)
    if (difference !== 0) return Math.sign(difference)
  }
  return 0
}

const textValue = (value) => String(value ?? '').trim()

export function validateAnnouncementInput(body, { partial = false } = {}) {
  const source = body && typeof body === 'object' ? body : {}
  const result = {}

  if (!partial || Object.hasOwn(source, 'type')) {
    const type = textValue(source.type)
    if (!announcementTypes.has(type)) throw Object.assign(new Error('Invalid announcement type'), { status: 400 })
    result.type = type
  }

  if (!partial || Object.hasOwn(source, 'title')) {
    const title = textValue(source.title)
    if (title.length < 3 || title.length > 120) {
      throw Object.assign(new Error('Announcement title must be between 3 and 120 characters'), { status: 400 })
    }
    result.title = title
  }

  if (!partial || Object.hasOwn(source, 'message')) {
    const message = textValue(source.message)
    if (message.length < 1 || message.length > 1000) {
      throw Object.assign(new Error('Announcement message must be between 1 and 1000 characters'), { status: 400 })
    }
    result.message = message
  }

  if (!partial || Object.hasOwn(source, 'priority')) {
    const priority = textValue(source.priority || 'normal')
    if (!announcementPriorities.has(priority)) {
      throw Object.assign(new Error('Invalid announcement priority'), { status: 400 })
    }
    result.priority = priority
  }

  if (!partial || Object.hasOwn(source, 'targetVersion')) {
    const targetVersion = textValue(source.targetVersion)
    if (targetVersion && !extensionVersionPattern.test(targetVersion)) {
      throw Object.assign(new Error('Target version must use numeric dotted version format'), { status: 400 })
    }
    result.targetVersion = targetVersion || null
  }

  if (!partial || Object.hasOwn(source, 'expiresAt')) {
    const expiresAt = textValue(source.expiresAt)
    const timestamp = expiresAt ? Date.parse(expiresAt) : Number.NaN
    if (expiresAt && !Number.isFinite(timestamp)) {
      throw Object.assign(new Error('Invalid announcement expiration date'), { status: 400 })
    }
    result.expiresAt = expiresAt ? new Date(timestamp).toISOString() : null
  }

  if (!partial || Object.hasOwn(source, 'isActive')) {
    if (typeof source.isActive !== 'boolean') {
      throw Object.assign(new Error('Announcement active state must be true or false'), { status: 400 })
    }
    result.isActive = source.isActive
  }

  const effectiveType = result.type ?? source.type
  const effectiveTargetVersion = Object.hasOwn(result, 'targetVersion')
    ? result.targetVersion
    : source.targetVersion
  if (!partial && effectiveType === 'update' && !effectiveTargetVersion) {
    throw Object.assign(new Error('Extension updates require a target version'), { status: 400 })
  }

  return result
}

export function mapAnnouncementRow(row) {
  return {
    id: row.id,
    type: row.type,
    title: row.title,
    message: row.message,
    priority: row.priority,
    targetVersion: row.target_version,
    isActive: Boolean(row.is_active),
    publishedAt: row.published_at,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

export function selectPublicAnnouncements(rows, installedVersion = '', now = Date.now()) {
  const validInstalledVersion = extensionVersionPattern.test(installedVersion) ? installedVersion : ''
  const active = rows
    .map(mapAnnouncementRow)
    .filter((announcement) => announcement.isActive && announcement.publishedAt &&
      Date.parse(announcement.publishedAt) <= now &&
      (!announcement.expiresAt || Date.parse(announcement.expiresAt) > now))

  const latestVersion = active
    .filter((announcement) => announcement.type === 'update' && announcement.targetVersion)
    .map((announcement) => announcement.targetVersion)
    .sort(compareExtensionVersions)
    .at(-1) ?? null

  const announcements = active.filter((announcement) =>
    announcement.type !== 'update' || !validInstalledVersion ||
    compareExtensionVersions(installedVersion, announcement.targetVersion) < 0)

  return {
    installedVersion: validInstalledVersion || null,
    latestVersion,
    updateAvailable: Boolean(validInstalledVersion && latestVersion &&
      compareExtensionVersions(installedVersion, latestVersion) < 0),
    announcements,
  }
}
