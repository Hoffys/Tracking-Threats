import { dbPromise, fromJson, toJson } from '../db/database.js'
import { createHash } from 'node:crypto'

export const methodologyVersion = '2026.09'
export const privacyNoticeVersion = '2026.09'

const parsePositiveInteger = (value, fallback) => {
  const parsed = Number.parseInt(value, 10)
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback
}

export const getScanRetentionDays = () =>
  parsePositiveInteger(process.env.SCAN_RETENTION_DAYS, 30)

export const getAuditRetentionDays = () =>
  parsePositiveInteger(process.env.AUDIT_RETENTION_DAYS, 90)

export const getScanExpiry = (createdAt = new Date()) => {
  const expiresAt = new Date(createdAt)
  expiresAt.setUTCDate(expiresAt.getUTCDate() + getScanRetentionDays())
  return expiresAt.toISOString()
}

export async function createScanSubmission({
  type,
  target,
  targetLabel,
  source,
  clientId,
  contentReceived,
}) {
  const db = await dbPromise
  const id = crypto.randomUUID()
  const submittedAt = new Date().toISOString()
  const targetHash = createHash('sha256').update(String(target ?? '')).digest('hex')
  await db.run(
    `INSERT INTO scan_submissions
      (id, client_id, scan_type, target_label, target_hash, source, processing_status, content_received, submitted_at)
      VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)`,
    id,
    clientId,
    type,
    targetLabel,
    targetHash,
    source,
    contentReceived ? 1 : 0,
    submittedAt,
  )
  await db.run(
    "UPDATE scan_submissions SET processing_status = 'scanning', started_at = ? WHERE id = ?",
    new Date().toISOString(),
    id,
  )
  return id
}

export async function completeScanSubmission(id, scanId) {
  const db = await dbPromise
  await db.run(
    `UPDATE scan_submissions
     SET scan_id = ?, processing_status = 'completed', completed_at = ?
     WHERE id = ?`,
    scanId,
    new Date().toISOString(),
    id,
  )
}

export async function failScanSubmission(id, error) {
  const db = await dbPromise
  await db.run(
    `UPDATE scan_submissions
     SET processing_status = 'failed', error_message = ?, completed_at = ?
     WHERE id = ?`,
    String(error?.message || 'Scan failed').slice(0, 500),
    new Date().toISOString(),
    id,
  )
}

export async function recordScanEvidence(db, scan, analysis) {
  const createdAt = scan.createdAt
  const providerResults = analysis.details?.threatIntel ?? []
  const providerWarnings = new Set(providerResults.map((item) => item?.warning).filter(Boolean))
  const localWarnings = (analysis.warningSigns ?? []).filter(
    (warning) => !providerWarnings.has(warning),
  )

  for (const warning of localWarnings) {
    await db.run(
      `INSERT INTO scan_evidence
        (id, scan_id, evidence_type, source, finding, matched, score_impact, details, created_at)
        VALUES (?, ?, 'rule', 'Local detection rule', ?, 1, 0, ?, ?)`,
      crypto.randomUUID(),
      scan.id,
      warning,
      toJson({ methodologyVersion }),
      createdAt,
    )
  }

  for (const provider of providerResults) {
    if (!provider?.provider) continue
    const finding = provider.error
      ? `Provider unavailable: ${provider.error}`
      : provider.warning || (provider.found ? 'Threat match reported' : 'No threat match')
    await db.run(
      `INSERT INTO scan_evidence
        (id, scan_id, evidence_type, source, finding, matched, score_impact, details, created_at)
        VALUES (?, ?, 'provider', ?, ?, ?, ?, ?, ?)`,
      crypto.randomUUID(),
      scan.id,
      provider.provider,
      finding,
      provider.found ? 1 : 0,
      Number(provider.deduction ?? 0),
      toJson(provider),
      createdAt,
    )
  }
}

export async function recordPrivacyConsent(db, scan, privacy = {}) {
  const accepted = privacy.accepted === true
  const processingBasis = accepted ? 'user-acknowledgment' : privacy.basis || 'service-request'
  await db.run(
    `INSERT INTO privacy_consents
      (id, scan_id, client_id, notice_version, accepted, processing_basis, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
    crypto.randomUUID(),
    scan.id,
    scan.clientId,
    privacy.noticeVersion || privacyNoticeVersion,
    accepted ? 1 : 0,
    processingBasis,
    scan.createdAt,
  )
}

const deleteClientRows = async (db, clientId) => {
  const scans = await db.all('SELECT id FROM scans WHERE client_id = ?', clientId)
  const scanIds = scans.map((row) => row.id)

  if (scanIds.length > 0) {
    const placeholders = scanIds.map(() => '?').join(', ')
    for (const table of [
      'scan_evidence',
      'privacy_consents',
      'email_scans',
      'message_scans',
      'live_monitor_activity',
      'alerts',
      'blocked_threats',
    ]) {
      await db.run(`DELETE FROM ${table} WHERE scan_id IN (${placeholders})`, ...scanIds)
    }
    await db.run(`DELETE FROM scans WHERE id IN (${placeholders})`, ...scanIds)
  }

  await db.run('DELETE FROM scan_submissions WHERE client_id = ?', clientId)

  const logs = await db.all('SELECT id, metadata FROM system_logs')
  const matchingLogIds = logs
    .filter((row) => fromJson(row.metadata, {}).clientId === clientId)
    .map((row) => row.id)
  if (matchingLogIds.length > 0) {
    const placeholders = matchingLogIds.map(() => '?').join(', ')
    await db.run(`DELETE FROM system_logs WHERE id IN (${placeholders})`, ...matchingLogIds)
  }

  return scanIds.length
}

export async function deleteClientScanData(clientId, { includeSettings = false } = {}) {
  const db = await dbPromise
  return db.transaction(async (transactionDb) => {
    const deletedScans = await deleteClientRows(transactionDb, clientId)
    if (includeSettings) {
      await transactionDb.run(
        'DELETE FROM notification_settings WHERE id = ?',
        `client:${clientId}`,
      )
    }
    return { deletedScans, settingsDeleted: includeSettings }
  })
}

export async function deleteAllScanData() {
  const db = await dbPromise
  await db.transaction(async (transactionDb) => {
    for (const table of [
      'scan_evidence',
      'privacy_consents',
      'scan_submissions',
      'email_scans',
      'message_scans',
      'live_monitor_activity',
      'alerts',
      'blocked_threats',
      'scans',
      'system_logs',
    ]) {
      await transactionDb.run(`DELETE FROM ${table}`)
    }
  })
}

export async function purgeExpiredData() {
  const db = await dbPromise
  const scansWithoutExpiry = await db.all(
    'SELECT id, created_at FROM scans WHERE expires_at IS NULL',
  )
  for (const scan of scansWithoutExpiry) {
    await db.run(
      'UPDATE scans SET expires_at = ? WHERE id = ?',
      getScanExpiry(scan.created_at),
      scan.id,
    )
  }
  const now = new Date().toISOString()
  const expiredScans = await db.all(
    'SELECT id FROM scans WHERE expires_at IS NOT NULL AND expires_at <= ?',
    now,
  )
  const ids = expiredScans.map((scan) => scan.id)
  if (ids.length > 0) {
    const placeholders = ids.map(() => '?').join(', ')
    await db.transaction(async (transactionDb) => {
      for (const table of [
        'scan_evidence',
        'privacy_consents',
        'scan_submissions',
        'email_scans',
        'message_scans',
        'live_monitor_activity',
        'alerts',
        'blocked_threats',
      ]) {
        await transactionDb.run(
          `DELETE FROM ${table} WHERE scan_id IN (${placeholders})`,
          ...ids,
        )
      }
      await transactionDb.run(`DELETE FROM scans WHERE id IN (${placeholders})`, ...ids)
    })
  }

  const auditCutoff = new Date()
  auditCutoff.setUTCDate(auditCutoff.getUTCDate() - getAuditRetentionDays())
  await db.run('DELETE FROM system_logs WHERE created_at < ?', auditCutoff.toISOString())
  await db.run(
    "DELETE FROM scan_submissions WHERE processing_status = 'failed' AND completed_at < ?",
    auditCutoff.toISOString(),
  )

  return { deletedScans: ids.length }
}
