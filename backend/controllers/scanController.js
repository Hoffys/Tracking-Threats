import { dbPromise, fromJson, toJson } from '../db/database.js'
import { analyzeEmail } from '../services/emailAnalyzer.js'
import { scanFile } from '../services/fileScanner.js'
import { scanMessage } from '../services/messageScanner.js'
import { sendScanReport } from '../services/mailReporter.js'
import { isMarkedSafeUrlTarget } from '../services/safeHosts.js'
import { enrichUrlAnalysis } from '../services/threatIntel.js'
import { scanUrl } from '../services/urlScanner.js'
import {
  completeScanSubmission,
  createScanSubmission,
  failScanSubmission,
  getScanExpiry,
  methodologyVersion,
  privacyNoticeVersion,
  recordPrivacyConsent,
  recordScanEvidence,
} from '../services/scanRepository.js'

const now = () => new Date().toISOString()
const uuid = () => crypto.randomUUID()
const visibleScanLimit = 50
const isPublicDeployment = () => process.env.PUBLIC_DEPLOYMENT === 'true'
const shouldStoreScanContent = () =>
  process.env.STORE_SCAN_CONTENT === 'true' ||
  (!isPublicDeployment() && process.env.STORE_SCAN_CONTENT !== 'false')

const getStoredContent = (content) => (shouldStoreScanContent() ? content : '')
const redactSensitiveText = (value = '') =>
  String(value)
    .replace(/https?:\/\/[^\s<>'"]+/gi, '[redacted URL]')
    .replace(/\b[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})\b/gi, '***@$1')

const getStoredTarget = (type, target = '') => {
  if (shouldStoreScanContent()) return target
  if (type === 'URL') return getDisplayDomain(target) || 'Redacted URL'
  if (type === 'Email') return getEmailDomain(target) || 'Redacted email scan'
  if (type === 'File') {
    const extension = String(target).toLowerCase().match(/\.([a-z0-9]{1,10})$/)?.[1]
    return extension ? `Redacted .${extension} file` : 'Redacted file'
  }
  return 'Redacted message scan'
}

const sanitizeDetailsForStorage = (value, key = '') => {
  if (shouldStoreScanContent() || value == null) return value
  if (['url', 'matches', 'addresses', 'fileName', 'extracted'].includes(key)) return undefined
  if (typeof value === 'string') return redactSensitiveText(value)
  if (Array.isArray(value)) {
    return value
      .map((item) => sanitizeDetailsForStorage(item))
      .filter((item) => item !== undefined)
  }
  if (typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .map(([childKey, childValue]) => [
          childKey,
          sanitizeDetailsForStorage(childValue, childKey),
        ])
        .filter(([, childValue]) => childValue !== undefined),
    )
  }
  return value
}
const normalizeClientId = (clientId) => {
  const normalized = String(clientId ?? '').trim()
  return /^[a-zA-Z0-9_-]{12,80}$/.test(normalized) ? normalized : null
}

const getDisplayDomain = (target) => {
  try {
    return new URL(target.includes('://') ? target : `https://${target}`).hostname
  } catch {
    return target
  }
}

const getEmailDomain = (sender = '') => {
  const match = sender.trim().toLowerCase().match(/@([a-z0-9.-]+\.[a-z]{2,})/i)
  return match?.[1] ?? ''
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
    clientId: row.client_id ?? details.clientId ?? null,
    submissionId: row.submission_id ?? null,
    processingStatus: row.processing_status ?? 'completed',
    methodologyVersion: row.methodology_version ?? methodologyVersion,
    contentRetained: row.content_retained === 1,
    expiresAt: row.expires_at ?? null,
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

async function persistScan({
  type,
  target,
  content,
  analysis,
  source = 'api',
  clientId = null,
  privacy = {},
  submissionId = null,
}) {
  const db = await dbPromise
  const createdAt = now()
  const storedContent = getStoredContent(content)
  const storedTarget = getStoredTarget(type, target)
  const storedClientId = normalizeClientId(clientId)
  const expiresAt = getScanExpiry(createdAt)
  const storedAnalysis = {
    ...analysis,
    warningSigns: (analysis.warningSigns ?? []).map(redactSensitiveText),
    details: sanitizeDetailsForStorage(analysis.details ?? {}),
  }
  const scan = {
    id: uuid(),
    type,
    target: storedTarget,
    content: storedContent,
    clientId: storedClientId,
    createdAt,
    ...storedAnalysis,
  }

  await db.run(
    `INSERT INTO scans
      (id, type, target, content, score, status, risk, action, summary, warning_signs, recommendations, details, client_id, submission_id, processing_status, methodology_version, content_retained, expires_at, history_visible, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
    toJson({ ...(scan.details ?? {}), source, clientId: storedClientId }),
    storedClientId,
    submissionId,
    'completed',
    methodologyVersion,
    storedContent ? 1 : 0,
    expiresAt,
    1,
    scan.createdAt,
  )

  await db.run(
    `INSERT INTO live_monitor_activity
      (id, scan_id, activity_type, source, target, domain, title, detail, score, status, risk_status, warning_signs, client_id, history_visible, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(scan_id) DO UPDATE SET
        activity_type = excluded.activity_type,
        source = excluded.source,
        target = excluded.target,
        domain = excluded.domain,
        title = excluded.title,
        detail = excluded.detail,
        score = excluded.score,
        status = excluded.status,
        risk_status = excluded.risk_status,
        warning_signs = excluded.warning_signs,
        client_id = excluded.client_id,
        history_visible = excluded.history_visible,
        created_at = excluded.created_at`,
    uuid(),
    scan.id,
    scan.type,
    source,
    scan.target,
    scan.type === 'URL' ? getDisplayDomain(scan.target) : scan.target,
    source === 'browser-extension' ? 'Browser URL scan' : `${scan.type} scan`,
    storedContent || scan.target,
    scan.score,
    scan.status === 'Dangerous' ? 'Blocked' : scan.status,
    scan.status,
    toJson(scan.warningSigns),
    storedClientId,
    1,
    scan.createdAt,
  )

  if (scan.status === 'Dangerous' || scan.score <= 50) {
    const recommendedAction = scan.recommendations?.[0] ?? 'Block the threat immediately.'
    await db.run(
      `INSERT INTO blocked_threats
        (id, scan_id, type, target, content, score, status, action, reason, recommended_action, review_status, active_visible, audit_visible, client_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      uuid(),
      scan.id,
      scan.type,
      scan.target,
      storedContent,
      scan.score,
      'Dangerous',
      'Blocked',
      scan.summary,
      recommendedAction,
      'active',
      1,
      1,
      storedClientId,
      createdAt,
    )
    await db.run(
      `INSERT INTO alerts
        (id, scan_id, title, source, severity, status, threat_type, risk_level, recommended_action, message, client_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
      storedClientId,
      createdAt,
    )
    await createSystemLog({
      level: 'warn',
      event: 'auto_block',
      message: `${scan.type} blocked: ${scan.target}`,
      metadata: { scanId: scan.id, source, clientId: storedClientId },
    })
  } else if (scan.status === 'Suspicious') {
    await db.run(
      `INSERT INTO alerts
        (id, scan_id, title, source, severity, status, threat_type, risk_level, recommended_action, message, client_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
      storedClientId,
      createdAt,
    )
  }

  await createSystemLog({
    level: 'info',
    event: 'scan_saved',
    message: `${scan.type} scan saved for ${scan.target}`,
    metadata: { scanId: scan.id, source, clientId: storedClientId },
  })

  await recordScanEvidence(db, scan, storedAnalysis)
  await recordPrivacyConsent(db, scan, privacy)

  await enforceVisibleScanLimit(db)

  const savedScan = mapScan({
    ...scan,
    warning_signs: toJson(scan.warningSigns),
    recommendations: toJson(scan.recommendations),
    details: toJson({ ...(scan.details ?? {}), source, clientId: storedClientId }),
    client_id: storedClientId,
    submission_id: submissionId,
    processing_status: 'completed',
    methodology_version: methodologyVersion,
    content_retained: storedContent ? 1 : 0,
    expires_at: expiresAt,
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

async function runWithSubmission(
  { type, target, content = '', source = 'api', clientId = null },
  operation,
) {
  const storedClientId = normalizeClientId(clientId)
  const submissionId = await createScanSubmission({
    type,
    target,
    targetLabel: getStoredTarget(type, target),
    source,
    clientId: storedClientId,
    contentReceived: Boolean(content),
  })

  try {
    const scan = await operation(submissionId)
    await completeScanSubmission(submissionId, scan.id)
    return scan
  } catch (error) {
    await failScanSubmission(submissionId, error)
    throw error
  }
}

export async function createUrlScan(target, source = 'api', clientId = null, privacy = {}) {
  return runWithSubmission({ type: 'URL', target, source, clientId }, async (submissionId) => {
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
        clientId,
        privacy,
        submissionId,
      })
    }

    const baseAnalysis = scanUrl(target)
    const analysis = await enrichUrlAnalysis(target, baseAnalysis)
    return persistScan({
      type: 'URL',
      target,
      content: '',
      analysis,
      source,
      clientId,
      privacy,
      submissionId,
    })
  })
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

export async function createMessageScan(
  { target, content },
  source = 'api',
  clientId = null,
  privacy = {},
) {
  return runWithSubmission(
    { type: 'Message', target, content, source, clientId },
    async (submissionId) => {
      const analysis = scanMessage(content)
      const storedTarget = shouldStoreScanContent() ? target : 'Public message scan'
      const scan = await persistScan({
        type: 'Message',
        target: storedTarget,
        content,
        analysis,
        source,
        clientId,
        privacy,
        submissionId,
      })
      const db = await dbPromise
      await db.run(
        `INSERT INTO message_scans
          (id, scan_id, target, message, score, status, risk, summary, warning_signs, recommendations, client_id, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        uuid(), scan.id, storedTarget, getStoredContent(content), scan.score, scan.status,
        scan.risk, scan.summary, toJson(scan.warningSigns), toJson(scan.recommendations),
        normalizeClientId(clientId), scan.date,
      )
      return scan
    },
  )
}

export async function createEmailScan(
  { sender, subject = '', body = '' },
  source = 'api',
  clientId = null,
  privacy = {},
) {
  const target = subject || sender || 'Email content without sender or subject'
  const content = `${subject}\n${body}`.trim()
  return runWithSubmission(
    { type: 'Email', target, content, source, clientId },
    async (submissionId) => {
      const analysis = analyzeEmail({ sender, subject, body })
      const storedSender = shouldStoreScanContent()
        ? sender || 'Unknown sender'
        : getEmailDomain(sender) || 'Sender redacted'
      const scan = await persistScan({
        type: 'Email', target, content, analysis, source, clientId, privacy, submissionId,
      })
      const db = await dbPromise
      await db.run(
        `INSERT INTO email_scans
          (id, scan_id, sender, subject, body, score, status, risk, summary, warning_signs, recommendations, client_id, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        uuid(), scan.id, storedSender, getStoredContent(subject), getStoredContent(body),
        scan.score, scan.status, scan.risk, scan.summary, toJson(scan.warningSigns),
        toJson(scan.recommendations), normalizeClientId(clientId), scan.date,
      )
      return scan
    },
  )
}

export async function createFileScan(
  { fileName, mimeType = '', size = 0, content = '', sha256 = '' },
  source = 'api',
  clientId = null,
  privacy = {},
) {
  const target = fileName || 'Uploaded file'
  return runWithSubmission(
    { type: 'File', target, content, source, clientId },
    async (submissionId) =>
      persistScan({
        type: 'File',
        target,
        content,
        analysis: await scanFile({ fileName, mimeType, size, content, sha256 }),
        source,
        clientId,
        privacy,
        submissionId,
      }),
  )
}

const getPrivacyContext = (body = {}, source = 'api') => ({
  accepted: body.privacyAccepted === true,
  noticeVersion: String(body.privacyNoticeVersion || privacyNoticeVersion).slice(0, 32),
  basis: source.startsWith('browser-') ? 'browser-extension-request' : 'service-request',
})

const validatePrivacyAcknowledgment = (req, source) => {
  if (
    isPublicDeployment() &&
    ['public-web-scan', 'browser-email-monitor'].includes(source) &&
    req.body.privacyAccepted !== true
  ) {
    return source === 'browser-email-monitor'
      ? 'Enable email scanning and accept the confidentiality notice first'
      : 'Accept the privacy notice before submitting a public scan'
  }
  return ''
}

export async function scanUrlHandler(req, res, next) {
  try {
    const target = req.body.url ?? req.body.target
    const source = req.body.source ?? 'api'
    const clientId = req.body.clientId
    if (!target) return res.status(400).json({ error: 'url is required' })
    if (req.body.preview === true) {
      return res.json(await previewUrlScan(target))
    }
    const privacyError = validatePrivacyAcknowledgment(req, source)
    if (privacyError) return res.status(400).json({ error: privacyError })
    res
      .status(201)
      .json(await createUrlScan(target, source, clientId, getPrivacyContext(req.body, source)))
  } catch (error) {
    next(error)
  }
}

export async function scanMessageHandler(req, res, next) {
  try {
    const content = req.body.message ?? req.body.content ?? req.body.body
    const target =
      req.body.target ??
      (shouldStoreScanContent() ? content?.slice(0, 56) : 'Public message scan') ??
      'Manual message scan'
    if (!content) return res.status(400).json({ error: 'message is required' })
    const source = req.body.source ?? 'api'
    const privacyError = validatePrivacyAcknowledgment(req, source)
    if (privacyError) return res.status(400).json({ error: privacyError })
    res
      .status(201)
      .json(
        await createMessageScan(
          { target, content },
          source,
          req.body.clientId,
          getPrivacyContext(req.body, source),
        ),
      )
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
    const source = req.body.source ?? 'api'
    const privacyError = validatePrivacyAcknowledgment(req, source)
    if (privacyError) return res.status(400).json({ error: privacyError })
    res
      .status(201)
      .json(
        await createFileScan(
          { fileName, mimeType, size, content, sha256 },
          source,
          req.body.clientId,
          getPrivacyContext(req.body, source),
        ),
      )
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
    const clientId = req.body.clientId
    if (!body && !subject) return res.status(400).json({ error: 'email content is required' })
    const privacyError = validatePrivacyAcknowledgment(req, source)
    if (privacyError) return res.status(400).json({ error: privacyError })
    res
      .status(201)
      .json(
        await createEmailScan(
          { sender, subject, body },
          source,
          clientId,
          getPrivacyContext(req.body, source),
        ),
      )
  } catch (error) {
    next(error)
  }
}
