import { dbPromise, fromJson, toJson } from '../db/database.js'
import { analyzeEmail } from '../services/emailAnalyzer.js'
import { scanFile } from '../services/fileScanner.js'
import { scanMessage } from '../services/messageScanner.js'
import { sendScanReport } from '../services/mailReporter.js'
import { isMarkedSafeUrlTarget } from '../services/safeHosts.js'
import { enrichUrlAnalysis } from '../services/threatIntel.js'
import { scanUrl } from '../services/urlScanner.js'

const now = () => new Date().toISOString()
const uuid = () => crypto.randomUUID()
const visibleScanLimit = 50

const getDisplayDomain = (target) => {
  try {
    return new URL(target.includes('://') ? target : `https://${target}`).hostname
  } catch {
    return target
  }
}

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
    threatIntel: details.threatIntel ?? [],
    emailBreakdown: details.emailBreakdown,
    fileDetails: details.file,
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
  warningSigns: fromJson(row.warning_signs),
  reviewStatus: row.review_status ?? 'active',
  activeVisible: row.active_visible !== 0,
  auditVisible: row.audit_visible !== 0,
  reviewedAt: row.reviewed_at,
  blockedAt: row.created_at,
  emailDetails:
    row.type === 'Email'
      ? {
          sender: row.email_sender || 'Sender not provided',
          subject: row.email_subject || 'Subject not provided',
          body: row.email_body ?? '',
        }
      : null,
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

async function enforceVisibleScanLimit(db) {
  const rowsToHide = await db.all(
    `
      SELECT id
      FROM scans
      WHERE history_visible = 1
      ORDER BY created_at DESC
      LIMIT -1 OFFSET ?
    `,
    visibleScanLimit,
  )

  if (rowsToHide.length === 0) return

  const scanIds = rowsToHide.map((row) => row.id)
  const placeholders = scanIds.map(() => '?').join(', ')

  await db.run(
    `UPDATE scans SET history_visible = 0 WHERE id IN (${placeholders})`,
    ...scanIds,
  )
  await db.run(
    `UPDATE live_monitor_activity SET history_visible = 0 WHERE scan_id IN (${placeholders})`,
    ...scanIds,
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
      (id, type, target, content, score, status, risk, action, summary, warning_signs, recommendations, details, history_visible, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
    1,
    scan.createdAt,
  )

  await db.run(
    `INSERT OR REPLACE INTO live_monitor_activity
      (id, scan_id, activity_type, source, target, domain, title, detail, score, status, risk_status, warning_signs, history_visible, created_at)
      VALUES (
        COALESCE((SELECT id FROM live_monitor_activity WHERE scan_id = ?), ?),
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )`,
    scan.id,
    uuid(),
    scan.id,
    scan.type,
    source,
    scan.target,
    scan.type === 'URL' ? getDisplayDomain(scan.target) : scan.target,
    source === 'browser-extension' ? 'Browser URL scan' : `${scan.type} scan`,
    scan.content || scan.target,
    scan.score,
    scan.status === 'Dangerous' ? 'Blocked' : scan.status,
    scan.status,
    toJson(scan.warningSigns),
    1,
    scan.createdAt,
  )

  if (scan.status === 'Dangerous' || scan.score <= 50) {
    const recommendedAction = scan.recommendations?.[0] ?? 'Block the threat immediately.'
    await db.run(
      `INSERT INTO blocked_threats
        (id, scan_id, type, target, content, score, status, action, reason, recommended_action, review_status, active_visible, audit_visible, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
      'active',
      1,
      1,
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

  await enforceVisibleScanLimit(db)

  const savedScan = mapScan({
    ...scan,
    warning_signs: toJson(scan.warningSigns),
    recommendations: toJson(scan.recommendations),
    details: toJson({ ...(scan.details ?? {}), source }),
    created_at: scan.createdAt,
  })

  try {
    const report = await sendScanReport(savedScan)
    if (report.sent) {
      await createSystemLog({
        event: 'scan_report_sent',
        message: `${scan.type} scan report emailed for ${scan.target}`,
        metadata: { scanId: scan.id },
      })
    }
  } catch (error) {
    await createSystemLog({
      level: 'error',
      event: 'scan_report_failed',
      message: error.message,
      metadata: { scanId: scan.id },
    })
  }

  return savedScan
}

export async function createUrlScan(target, source = 'api') {
  if (await isMarkedSafeUrlTarget(target)) {
    return persistScan({
      type: 'URL',
      target,
      content: '',
      analysis: {
        score: 100,
        status: 'Safe',
        risk: 'low',
        action: 'Allowed',
        summary: 'This URL was previously marked safe during review.',
        warningSigns: [],
        recommendations: ['Allow this URL unless new suspicious behavior appears.'],
        recommendation: 'Allow this URL unless new suspicious behavior appears.',
        details: { threatIntel: [] },
      },
      source,
    })
  }

  const baseAnalysis = scanUrl(target)
  const analysis = await enrichUrlAnalysis(target, baseAnalysis)
  return persistScan({ type: 'URL', target, content: '', analysis, source })
}

export async function previewUrlScan(target) {
  if (await isMarkedSafeUrlTarget(target)) {
    return {
      type: 'URL',
      target,
      content: '',
      score: 100,
      status: 'Safe',
      risk: 'low',
      action: 'Allowed',
      summary: 'This URL was previously marked safe during review.',
      warningSigns: [],
      recommendations: ['Allow this URL unless new suspicious behavior appears.'],
      recommendation: 'Allow this URL unless new suspicious behavior appears.',
      threatIntel: [],
      responseStatus: null,
      blocked: false,
    }
  }

  const baseAnalysis = scanUrl(target)
  const analysis = await enrichUrlAnalysis(target, baseAnalysis)

  return {
    type: 'URL',
    target,
    content: '',
    score: analysis.score,
    status: analysis.status,
    risk: analysis.risk,
    action: analysis.action,
    summary: analysis.summary,
    warningSigns: analysis.warningSigns ?? [],
    recommendations: analysis.recommendations ?? [],
    recommendation: analysis.recommendation,
    threatIntel: analysis.details?.threatIntel ?? [],
    responseStatus: analysis.action === 'Blocked' ? 'Blocked' : null,
    blocked: analysis.action === 'Blocked',
  }
}

export async function createMessageScan({ target, content }, source = 'api') {
  const analysis = scanMessage(content)
  const scan = await persistScan({ type: 'Message', target, content, analysis, source })

  const db = await dbPromise
  await db.run(
    `INSERT INTO message_scans
      (id, scan_id, target, message, score, status, risk, summary, warning_signs, recommendations, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    uuid(),
    scan.id,
    target,
    content,
    scan.score,
    scan.status,
    scan.risk,
    scan.summary,
    toJson(scan.warningSigns),
    toJson(scan.recommendations),
    scan.date,
  )

  return scan
}

export async function createEmailScan({ sender, subject = '', body = '' }, source = 'api') {
  const analysis = analyzeEmail({ sender, subject, body })
  const scan = await persistScan({
    type: 'Email',
    target: subject || sender || 'Email content without sender or subject',
    content: `${subject}\n${body}`.trim(),
    analysis,
    source,
  })

  const db = await dbPromise
  await db.run(
    `INSERT INTO email_scans
      (id, scan_id, sender, subject, body, score, status, risk, summary, warning_signs, recommendations, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    uuid(),
    scan.id,
    sender || 'Unknown sender',
    subject,
    body,
    scan.score,
    scan.status,
    scan.risk,
    scan.summary,
    toJson(scan.warningSigns),
    toJson(scan.recommendations),
    scan.date,
  )

  return scan
}

export async function createFileScan(
  { fileName, mimeType = '', size = 0, content = '', sha256 = '' },
  source = 'api',
) {
  return persistScan({
    type: 'File',
    target: fileName || 'Uploaded file',
    content,
    analysis: await scanFile({ fileName, mimeType, size, content, sha256 }),
    source,
  })
}

export async function scanUrlHandler(req, res, next) {
  try {
    const target = req.body.url ?? req.body.target
    const source = req.body.source ?? 'api'
    if (!target) return res.status(400).json({ error: 'url is required' })
    if (req.body.preview === true) {
      return res.json(await previewUrlScan(target))
    }
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

export async function scanFileHandler(req, res, next) {
  try {
    const fileName = req.body.fileName ?? req.body.name ?? req.body.target
    const mimeType = req.body.mimeType ?? req.body.type ?? ''
    const size = Number(req.body.size ?? 0)
    const content = req.body.content ?? ''
    const sha256 = req.body.sha256 ?? ''
    if (!fileName) return res.status(400).json({ error: 'fileName is required' })
    res.status(201).json(await createFileScan({ fileName, mimeType, size, content, sha256 }))
  } catch (error) {
    next(error)
  }
}

export async function scanEmailHandler(req, res, next) {
  try {
    const sender = req.body.sender ?? req.body.target ?? ''
    const subject = req.body.subject ?? ''
    const body = req.body.body ?? req.body.content ?? ''
    const source = req.body.source ?? 'api'
    if (!body && !subject) return res.status(400).json({ error: 'email content is required' })
    res.status(201).json(await createEmailScan({ sender, subject, body }, source))
  } catch (error) {
    next(error)
  }
}
