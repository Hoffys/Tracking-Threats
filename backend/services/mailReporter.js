import nodemailer from 'nodemailer'
import { dbPromise, fromJson } from '../db/database.js'
import { readNotificationSettings } from './notificationSettings.js'

let transporter

const getSmtpConfig = () => {
  const host = process.env.SMTP_HOST
  const user = process.env.SMTP_USER
  const pass = process.env.SMTP_PASS
  if (!host || !user || !pass) return null

  const port = Number(process.env.SMTP_PORT ?? 465)
  return {
    host,
    port,
    secure: process.env.SMTP_SECURE ? process.env.SMTP_SECURE === 'true' : port === 465,
    auth: { user, pass },
  }
}

const getTransporter = () => {
  const config = getSmtpConfig()
  if (!config) return null
  if (!transporter) transporter = nodemailer.createTransport(config)
  return transporter
}

export const isMailConfigured = () => Boolean(getSmtpConfig())

const formatWarnings = (warnings = []) =>
  warnings.length > 0 ? warnings.map((warning) => `- ${warning}`).join('\n') : '- None'

const formatRecommendations = (recommendations = []) =>
  recommendations.length > 0
    ? recommendations.map((recommendation) => `- ${recommendation}`).join('\n')
    : '- Review the scan inside Tracking Threats.'

const sendTextMail = async ({ recipients, subject, text }) => {
  const smtp = getTransporter()
  if (!smtp || recipients.length === 0) return { sent: false, skipped: true }

  const result = await smtp.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: recipients,
    subject,
    text,
  })
  return { sent: true, messageId: result.messageId }
}

export async function sendScanReport(scan) {
  const settings = await readNotificationSettings()
  if (!settings.emailScanReports || settings.reportEmails.length === 0) {
    return { sent: false, skipped: true }
  }

  return sendTextMail({
    recipients: settings.reportEmails,
    subject: `[Tracking Threats] ${scan.status} ${scan.type} scan`,
    text: [
      'Tracking Threats scan summary',
      '',
      `Type: ${scan.type}`,
      `Target: ${scan.target}`,
      `Status: ${scan.status}`,
      `Action: ${scan.action}`,
      `Safety score: ${scan.score}/100`,
      `Scanned at: ${scan.date}`,
      '',
      scan.summary,
      '',
      'Warning signs:',
      formatWarnings(scan.warningSigns),
      '',
      'Recommendations:',
      formatRecommendations(scan.recommendations),
    ].join('\n'),
  })
}

export async function sendHistoryDigest() {
  const settings = await readNotificationSettings()
  if (!settings.emailHistoryDigest || settings.reportEmails.length === 0) {
    return { sent: false, skipped: true }
  }

  const db = await dbPromise
  const [scans, reviewedThreats] = await Promise.all([
    db.all(`
      SELECT type, target, score, status, action, created_at
      FROM scans
      WHERE history_visible = 1
      ORDER BY created_at DESC
      LIMIT 25
    `),
    db.all(`
      SELECT
        blocked_threats.type,
        blocked_threats.target,
        blocked_threats.score,
        blocked_threats.review_status,
        blocked_threats.reviewed_at,
        scans.warning_signs
      FROM blocked_threats
      LEFT JOIN scans ON scans.id = blocked_threats.scan_id
      WHERE blocked_threats.review_status != 'active'
        AND blocked_threats.audit_visible = 1
      ORDER BY COALESCE(blocked_threats.reviewed_at, blocked_threats.created_at) DESC
      LIMIT 25
    `),
  ])

  const scanLines =
    scans.length > 0
      ? scans.map(
          (scan) =>
            `- ${scan.created_at}: ${scan.type} ${scan.status} ${scan.score}/100 - ${scan.target}`,
        )
      : ['- No visible scan history.']
  const reviewLines =
    reviewedThreats.length > 0
      ? reviewedThreats.map((threat) => {
          const warningCount = fromJson(threat.warning_signs).length
          return `- ${threat.reviewed_at}: ${threat.type} ${threat.review_status} ${threat.score}/100 - ${threat.target} (${warningCount} warning signs)`
        })
      : ['- No reviewed threat records.']

  return sendTextMail({
    recipients: settings.reportEmails,
    subject: '[Tracking Threats] Scan history digest',
    text: [
      'Tracking Threats history digest',
      '',
      'Recent scans:',
      ...scanLines,
      '',
      'Reviewed threats:',
      ...reviewLines,
    ].join('\n'),
  })
}
