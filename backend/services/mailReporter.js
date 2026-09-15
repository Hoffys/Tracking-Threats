import dns from 'node:dns/promises'
import net from 'node:net'
import nodemailer from 'nodemailer'
import { dbPromise, fromJson } from '../db/database.js'
import { readNotificationSettings } from './notificationSettings.js'

let transporter
let transporterKey

const cleanEnv = (value = '') => {
  const trimmed = String(value ?? '').trim()
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1).trim()
  }
  return trimmed
}

const isSmtpEnabled = () => cleanEnv(process.env.SMTP_ENABLED).toLowerCase() !== 'false'

export const getMailConfigStatus = () => {
  const enabled = isSmtpEnabled()
  const required = {
    SMTP_HOST: Boolean(cleanEnv(process.env.SMTP_HOST)),
    SMTP_USER: Boolean(cleanEnv(process.env.SMTP_USER)),
    SMTP_PASS: Boolean(cleanEnv(process.env.SMTP_PASS)),
  }
  const missing = Object.entries(required)
    .filter(([, isSet]) => !isSet)
    .map(([name]) => name)

  return {
    configured: enabled && missing.length === 0,
    enabled,
    missing,
  }
}

const getSmtpConfig = () => {
  if (!isSmtpEnabled()) return null

  const host = cleanEnv(process.env.SMTP_HOST)
  const user = cleanEnv(process.env.SMTP_USER)
  const pass = cleanEnv(process.env.SMTP_PASS)
  if (!host || !user || !pass) return null

  const port = Number(cleanEnv(process.env.SMTP_PORT) || 465)
  return {
    host,
    port,
    secure: cleanEnv(process.env.SMTP_SECURE)
      ? cleanEnv(process.env.SMTP_SECURE).toLowerCase() === 'true'
      : port === 465,
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000,
    auth: { user, pass: pass.replace(/\s/g, '') },
  }
}

const resolveSmtpConfig = async (config) => {
  if (net.isIP(config.host)) return config

  const { address } = await dns.lookup(config.host, { family: 4 })
  return {
    ...config,
    host: address,
    tls: {
      rejectUnauthorized:
        cleanEnv(process.env.SMTP_TLS_REJECT_UNAUTHORIZED).toLowerCase() !== 'false',
      servername: config.host,
    },
  }
}

const getTransporter = async () => {
  const config = getSmtpConfig()
  if (!config) return null
  const key = `${config.host}:${config.port}:${config.auth.user}:${config.secure}`
  if (!transporter || transporterKey !== key) {
    transporter = nodemailer.createTransport(await resolveSmtpConfig(config))
    transporterKey = key
  }
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
  const smtp = await getTransporter()
  if (!smtp || recipients.length === 0) return { sent: false, skipped: true }

  const result = await smtp.sendMail({
    from: cleanEnv(process.env.SMTP_FROM) || cleanEnv(process.env.SMTP_USER),
    to: recipients,
    subject,
    text,
  })
  return { sent: true, messageId: result.messageId }
}

export async function sendScanReport(scan) {
  const settings = await readNotificationSettings(scan.clientId)
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

export async function sendHistoryDigest(clientId = '') {
  const settings = await readNotificationSettings(clientId)
  if (!settings.emailHistoryDigest || settings.reportEmails.length === 0) {
    return { sent: false, skipped: true }
  }

  const db = await dbPromise
  const scanClientFilter = clientId ? 'AND client_id = ?' : ''
  const scanClientParams = clientId ? [clientId] : []
  const [scans, reviewedThreats] = await Promise.all([
    db.all(
      `
      SELECT type, target, score, status, action, created_at
      FROM scans
      WHERE history_visible = 1
        ${scanClientFilter}
      ORDER BY created_at DESC
      LIMIT 25
    `,
      ...scanClientParams,
    ),
    db.all(
      `
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
        ${clientId ? 'AND blocked_threats.client_id = ?' : ''}
      ORDER BY COALESCE(blocked_threats.reviewed_at, blocked_threats.created_at) DESC
      LIMIT 25
    `,
      ...(clientId ? [clientId] : []),
    ),
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
