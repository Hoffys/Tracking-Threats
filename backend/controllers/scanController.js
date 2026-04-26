import { dbPromise, fromJson, toJson } from '../db/database.js'
import { analyzeEmail } from '../services/emailAnalyzer.js'
import { scanMessage } from '../services/messageScanner.js'
import { scanUrl } from '../services/urlScanner.js'

const now = () => new Date().toISOString()
const uuid = () => crypto.randomUUID()

export const mapScan = (row) => {
  const details = fromJson(row.details, {})
  return {
    id: row.id,
    type: row.type,
    target: row.target,
    content: row.content ?? '',
    score: row.score,
    status: row.status,
    risk: row.risk,
    action: row.action,
    summary: row.summary,
    warningSigns: fromJson(row.warning_signs),
    recommendations: fromJson(row.recommendations),
    recommendation: fromJson(row.recommendations).join(' '),
    source: details.source ?? 'api',
    emailBreakdown: details.emailBreakdown,
    responseStatus: row.action === 'Blocked' ? 'Blocked' : null,
    blocked: row.action === 'Blocked',
    date: row.created_at,
  }
}

export const mapAlert = (row) => ({
  id: row.id,
  scanId: row.scan_id,
  title: row.title,
  source: row.source,
  severity: row.severity,
  status: row.status,
  threatType: row.threat_type,
  riskLevel: row.risk_level,
  recommendedAction: row.recommended_action,
  message: row.message,
  time: row.created_at,
})

export const mapBlockedThreat = (row) => ({
  id: row.id,
  scanId: row.scan_id,
  type: row.type,
  target: row.target,
  content: row.content ?? '',
  score: row.score,
  status: row.status,
  action: row.action,
  reason: row.reason,
  recommendedAction: row.recommended_action,
  blockedAt: row.created_at,
})

export async function createSystemLog({ level = 'info', event, message, metadata = {} }) {
  const db = await dbPromise
  await db.run(
    'INSERT INTO system_logs (id, level, event, message, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    uuid(),
    level,
    event,
    message,
    toJson(metadata),
    now(),
  )
}

async function persistScan({ type, target, content, analysis, source = 'api' }) {
  const db = await dbPromise
  const createdAt = now()
  const scan = {
    id: uuid(),
    type,
    target,
    content,
    createdAt,
    ...analysis,
  }

  await db.run(
    `INSERT INTO scans
      (id, type, target, content, score, status, risk, action, summary, warning_signs, recommendations, details, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    scan.id,
    scan.type,
    scan.target,
    scan.content,
    scan.score,
    scan.status,
    scan.risk,
    scan.action,
    scan.summary,
    toJson(scan.warningSigns),
    toJson(scan.recommendations),
    toJson({ ...(scan.details ?? {}), source }),
    scan.createdAt,
  )

  if (scan.status === 'Dangerous' || scan.score <= 49) {
    const recommendedAction = scan.recommendations?.[0] ?? 'Block the threat immediately.'
    await db.run(
      `INSERT INTO blocked_threats
        (id, scan_id, type, target, content, score, status, action, reason, recommended_action, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      uuid(),
      scan.id,
      scan.type,
      scan.target,
      scan.content,
      scan.score,
      'Dangerous',
      'Blocked',
      scan.summary,
      recommendedAction,
      createdAt,
    )
    await db.run(
      `INSERT INTO alerts
        (id, scan_id, title, source, severity, status, threat_type, risk_level, recommended_action, message, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      uuid(),
      scan.id,
      'Dangerous Threat Detected',
      scan.target,
      'critical',
      'new',
      scan.type,
      'Dangerous',
      recommendedAction,
      `${scan.type} was automatically blocked.`,
      createdAt,
    )
    await createSystemLog({
      level: 'warn',
      event: 'auto_block',
      message: `${scan.type} blocked: ${scan.target}`,
      metadata: { scanId: scan.id, source },
    })
  } else if (scan.status === 'Suspicious') {
    await db.run(
      `INSERT INTO alerts
        (id, scan_id, title, source, severity, status, threat_type, risk_level, recommended_action, message, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      uuid(),
      scan.id,
      `Suspicious ${scan.type} detected`,
      scan.target,
      scan.risk,
      'new',
      scan.type,
      scan.status,
      scan.recommendations?.[0] ?? 'Review before trusting.',
      scan.summary,
      createdAt,
    )
  }

  await createSystemLog({
    level: 'info',
    event: 'scan_saved',
    message: `${scan.type} scan saved for ${scan.target}`,
    metadata: { scanId: scan.id, source },
  })

  return mapScan({
    ...scan,
    warning_signs: toJson(scan.warningSigns),
    recommendations: toJson(scan.recommendations),
    details: toJson({ ...(scan.details ?? {}), source }),
    created_at: scan.createdAt,
  })
}

export async function createUrlScan(target, source = 'api') {
  return persistScan({ type: 'URL', target, content: '', analysis: scanUrl(target), source })
}

export async function createMessageScan({ target, content }, source = 'api') {
  return persistScan({ type: 'Message', target, content, analysis: scanMessage(content), source })
}

export async function createEmailScan({ sender, subject = '', body = '' }, source = 'api') {
  return persistScan({
    type: 'Email',
    target: sender || subject || 'Untitled email',
    content: `${subject}\n${body}`.trim(),
    analysis: analyzeEmail({ sender, subject, body }),
    source,
  })
}

export async function scanUrlHandler(req, res, next) {
  try {
    const target = req.body.url ?? req.body.target
    const source = req.body.source ?? 'api'
    if (!target) return res.status(400).json({ error: 'url is required' })
    res.status(201).json(await createUrlScan(target, source))
  } catch (error) {
    next(error)
  }
}

export async function scanMessageHandler(req, res, next) {
  try {
    const content = req.body.message ?? req.body.content ?? req.body.body
    const target = req.body.target ?? content?.slice(0, 56) ?? 'Manual message scan'
    if (!content) return res.status(400).json({ error: 'message is required' })
    res.status(201).json(await createMessageScan({ target, content }))
  } catch (error) {
    next(error)
  }
}

export async function scanEmailHandler(req, res, next) {
  try {
    const sender = req.body.sender ?? req.body.target ?? ''
    const subject = req.body.subject ?? ''
    const body = req.body.body ?? req.body.content ?? ''
    if (!body && !subject) return res.status(400).json({ error: 'email content is required' })
    res.status(201).json(await createEmailScan({ sender, subject, body }))
  } catch (error) {
    next(error)
  }
}
