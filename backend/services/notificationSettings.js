import { dbPromise, fromJson, toJson } from '../db/database.js'

export const defaultNotificationSettings = {
  reportEmails: [],
  emailScanReports: true,
  emailHistoryDigest: true,
}

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

const normalizeEmails = (emails = []) =>
  [...new Set(emails.map((email) => email.trim().toLowerCase()).filter(Boolean))]

export function validateNotificationSettings(input = {}) {
  const reportEmails = normalizeEmails(Array.isArray(input.reportEmails) ? input.reportEmails : [])
  if (reportEmails.some((email) => !emailPattern.test(email))) {
    throw new Error('reportEmails must contain valid email addresses')
  }

  return {
    reportEmails,
    emailScanReports: input.emailScanReports !== false,
    emailHistoryDigest: input.emailHistoryDigest !== false,
  }
}

export async function readNotificationSettings() {
  const db = await dbPromise
  const row = await db.get("SELECT * FROM notification_settings WHERE id = 'default'")
  if (!row) return defaultNotificationSettings

  return {
    reportEmails: fromJson(row.report_emails),
    emailScanReports: row.email_scan_reports !== 0,
    emailHistoryDigest: row.email_history_digest !== 0,
  }
}

export async function writeNotificationSettings(input) {
  const settings = validateNotificationSettings(input)
  const db = await dbPromise
  await db.run(
    `INSERT INTO notification_settings
      (id, report_emails, email_scan_reports, email_history_digest, updated_at)
      VALUES ('default', ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        report_emails = excluded.report_emails,
        email_scan_reports = excluded.email_scan_reports,
        email_history_digest = excluded.email_history_digest,
        updated_at = excluded.updated_at`,
    toJson(settings.reportEmails),
    settings.emailScanReports ? 1 : 0,
    settings.emailHistoryDigest ? 1 : 0,
    new Date().toISOString(),
  )

  return settings
}
