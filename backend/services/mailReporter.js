import nodemailer from 'nodemailer'
import { dbPromise, fromJson } from '../db/database.js'
import { readNotificationSettings } from './notificationSettings.js'

let transporter
let transporterKey

const cleanEnv = (value = '') => {
  const trimmed = String(value ?? '')
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .trim()
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1).trim()
  }
  return trimmed
}

const cleanHost = (value = '') => {
  let host = cleanEnv(value)
  if (host.includes('=')) host = host.split('=').pop().trim()
  host = host.replace(/^https?:\/\//i, '').split('/')[0].trim()
  return host
}

const isSmtpEnabled = () => cleanEnv(process.env.SMTP_ENABLED).toLowerCase() !== 'false'

export const getMailConfigStatus = () => {
  const smtpEnabled = isSmtpEnabled()
  const smtpRequired = {
    SMTP_HOST: Boolean(cleanHost(process.env.SMTP_HOST)),
    SMTP_USER: Boolean(cleanEnv(process.env.SMTP_USER)),
    SMTP_PASS: Boolean(cleanEnv(process.env.SMTP_PASS)),
  }
  const smtpMissing = Object.entries(smtpRequired)
    .filter(([, isSet]) => !isSet)
    .map(([name]) => name)
  const resendFrom = cleanEnv(process.env.RESEND_FROM) || cleanEnv(process.env.SMTP_FROM)
  const resendRequired = {
    RESEND_API_KEY: Boolean(cleanEnv(process.env.RESEND_API_KEY)),
    RESEND_FROM: Boolean(resendFrom),
  }
  const resendMissing = Object.entries(resendRequired)
    .filter(([, isSet]) => !isSet)
    .map(([name]) => name)
  const smtpConfigured = smtpEnabled && smtpMissing.length === 0
  const resendConfigured = resendMissing.length === 0

  return {
    configured: smtpConfigured || resendConfigured,
    enabled: smtpEnabled || resendConfigured,
    provider: resendConfigured ? 'resend' : smtpConfigured ? 'smtp' : null,
    missing: smtpEnabled ? smtpMissing : resendMissing,
    smtp: {
      configured: smtpConfigured,
      enabled: smtpEnabled,
      host: cleanHost(process.env.SMTP_HOST) || null,
      missing: smtpMissing,
    },
    resend: {
      configured: resendConfigured,
      missing: resendMissing,
    },
  }
}

const getSmtpConfig = () => {
  if (!isSmtpEnabled()) return null

  const host = cleanHost(process.env.SMTP_HOST)
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

const getTransporter = async () => {
  const config = getSmtpConfig()
  if (!config) return null
  const key = `${config.host}:${config.port}:${config.auth.user}:${config.secure}`
  if (!transporter || transporterKey !== key) {
    transporter = nodemailer.createTransport({
      ...config,
      tls: {
        rejectUnauthorized:
          cleanEnv(process.env.SMTP_TLS_REJECT_UNAUTHORIZED).toLowerCase() !== 'false',
        servername: config.host,
      },
    })
    transporterKey = key
  }
  return transporter
}

export const isResendConfigured = () =>
  Boolean(cleanEnv(process.env.RESEND_API_KEY)) &&
  Boolean(cleanEnv(process.env.RESEND_FROM) || cleanEnv(process.env.SMTP_FROM))

export const isMailConfigured = () => Boolean(getSmtpConfig()) || isResendConfigured()

const formatWarnings = (warnings = []) =>
  warnings.length > 0 ? warnings.map((warning) => `- ${warning}`).join('\n') : '- None'

const formatRecommendations = (recommendations = []) =>
  recommendations.length > 0
    ? recommendations.map((recommendation) => `- ${recommendation}`).join('\n')
    : '- Review the scan inside Tracking Threats.'

const getDeliveryErrorMessage = (error) => {
  const responseCode = Number(error?.responseCode ?? 0)
  const code = error?.code ?? ''
  const command = error?.command ? ` (${error.command})` : ''

  if (responseCode === 535) {
    return 'Gmail rejected the SMTP login. Use a Google App Password for SMTP_PASS, not your normal Gmail password.'
  }
  if (responseCode === 534) {
    return 'Gmail blocked this SMTP login. Enable 2-Step Verification and create a Google App Password.'
  }
  if (responseCode === 550 || responseCode === 553) {
    return 'Gmail rejected the sender address. Make SMTP_FROM match SMTP_USER or use a verified sender.'
  }
  if (['EAUTH', 'EENVELOPE'].includes(code)) {
    return `Email delivery failed: ${error.message}${command}`
  }
  if (['ECONNECTION', 'ESOCKET', 'ETIMEDOUT', 'ENOTFOUND'].includes(code)) {
    return `Email delivery failed: cannot connect to SMTP server ${cleanHost(
      process.env.SMTP_HOST,
    ) || '(missing host)'} (${code}). Try SMTP_HOST=smtp.gmail.com, SMTP_PORT=587, and SMTP_SECURE=false, then redeploy.`
  }

  return `Email delivery failed: ${error?.message || 'SMTP server rejected the message.'}${command}`
}

const sendTextMail = async ({ recipients, subject, text }) => {
  try {
    if (isResendConfigured()) {
      return sendResendMail({ recipients, subject, text })
    }

    const smtp = await getTransporter()
    if (!smtp || recipients.length === 0) return { sent: false, skipped: true }

    const result = await smtp.sendMail({
      from: cleanEnv(process.env.SMTP_FROM) || cleanEnv(process.env.SMTP_USER),
      to: recipients,
      subject,
      text,
    })
    return { sent: true, messageId: result.messageId }
  } catch (error) {
    const deliveryError = new Error(getDeliveryErrorMessage(error))
    deliveryError.isMailDeliveryError = true
    throw deliveryError
  }
}

const sendResendMail = async ({ recipients, subject, text }) => {
  if (recipients.length === 0) return { sent: false, skipped: true }

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${cleanEnv(process.env.RESEND_API_KEY)}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: cleanEnv(process.env.RESEND_FROM) || cleanEnv(process.env.SMTP_FROM),
      to: recipients,
      subject,
      text,
    }),
  })

  const payload = await response.json().catch(() => ({}))
  if (!response.ok) {
    const deliveryError = new Error(
      `Email delivery failed through Resend: ${
        payload?.message || payload?.error || `HTTP ${response.status}`
      }`,
    )
    deliveryError.isMailDeliveryError = true
    throw deliveryError
  }

  return { sent: true, messageId: payload.id }
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
