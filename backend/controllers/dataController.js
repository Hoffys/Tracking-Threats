import { dbPromise, fromJson } from '../db/database.js'
import { mapAlert, mapBlockedThreat, mapScan } from './scanController.js'

const getDisplayDomain = (target) => {
  try {
    return new URL(target.includes('://') ? target : `https://${target}`).hostname
  } catch {
    return target
  }
}

async function syncLiveMonitorActivity(db) {
  const rows = await db.all(`
    SELECT scans.*
    FROM scans
    LEFT JOIN live_monitor_activity ON live_monitor_activity.scan_id = scans.id
    WHERE scans.history_visible = 1
      AND (
        live_monitor_activity.scan_id IS NULL
        OR live_monitor_activity.history_visible != scans.history_visible
      )
    ORDER BY scans.created_at DESC
    LIMIT 250
  `)

  for (const row of rows) {
    const scan = mapScan(row)
    await db.run(
      `INSERT OR REPLACE INTO live_monitor_activity
        (id, scan_id, activity_type, source, target, domain, title, detail, score, status, risk_status, warning_signs, history_visible, created_at)
        VALUES (
          COALESCE((SELECT id FROM live_monitor_activity WHERE scan_id = ?), ?),
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )`,
      scan.id,
      crypto.randomUUID(),
      scan.id,
      scan.type,
      scan.source,
      scan.target,
      scan.type === 'URL' ? getDisplayDomain(scan.target) : scan.target,
      scan.source === 'browser-extension' ? 'Browser URL scan' : `${scan.type} scan`,
      scan.content || scan.target,
      scan.score,
      scan.status === 'Dangerous' ? 'Blocked' : scan.status,
      scan.status,
      JSON.stringify(scan.warningSigns ?? []),
      1,
      scan.date,
    )
  }
}

export async function getHistory(_req, res, next) {
  try {
    const db = await dbPromise
    const rows = await db.all(`
      SELECT * FROM scans
      WHERE history_visible = 1
      ORDER BY created_at DESC
      LIMIT 50
    `)
    res.json(rows.map(mapScan))
  } catch (error) {
    next(error)
  }
}

export async function clearHistory(_req, res, next) {
  try {
    const db = await dbPromise
    await db.run('UPDATE scans SET history_visible = 0')
    await db.run('UPDATE live_monitor_activity SET history_visible = 0')
    res.json({ ok: true })
  } catch (error) {
    next(error)
  }
}

export async function getAlerts(_req, res, next) {
  try {
    const db = await dbPromise
    const rows = await db.all('SELECT * FROM alerts ORDER BY created_at DESC LIMIT 250')
    res.json(rows.map(mapAlert))
  } catch (error) {
    next(error)
  }
}

export async function dismissAlert(req, res, next) {
  try {
    const db = await dbPromise
    await db.run('UPDATE alerts SET status = ? WHERE id = ?', 'acknowledged', req.params.id)
    res.json({ ok: true })
  } catch (error) {
    next(error)
  }
}

export async function clearAlerts(_req, res, next) {
  try {
    const db = await dbPromise
    await db.run('DELETE FROM alerts')
    res.json({ ok: true })
  } catch (error) {
    next(error)
  }
}

export async function getBlockedThreats(_req, res, next) {
  try {
    const db = await dbPromise
    const rows = await db.all(`
      SELECT blocked_threats.*, scans.warning_signs
      FROM blocked_threats
      LEFT JOIN scans ON scans.id = blocked_threats.scan_id
      WHERE blocked_threats.active_visible = 1
      ORDER BY blocked_threats.created_at DESC
      LIMIT 250
    `)
    res.json(rows.map(mapBlockedThreat))
  } catch (error) {
    next(error)
  }
}

export async function getThreatAuditLogs(_req, res, next) {
  try {
    const db = await dbPromise
    const rows = await db.all(`
      SELECT blocked_threats.*, scans.warning_signs
      FROM blocked_threats
      LEFT JOIN scans ON scans.id = blocked_threats.scan_id
      WHERE blocked_threats.review_status != 'active'
        AND blocked_threats.audit_visible = 1
      ORDER BY COALESCE(blocked_threats.reviewed_at, blocked_threats.created_at) DESC
      LIMIT 250
    `)
    res.json(rows.map(mapBlockedThreat))
  } catch (error) {
    next(error)
  }
}

export async function clearThreatAuditLogs(_req, res, next) {
  try {
    const db = await dbPromise
    await db.run(
      "UPDATE blocked_threats SET audit_visible = 0 WHERE review_status != 'active'",
    )
    res.json({ ok: true })
  } catch (error) {
    next(error)
  }
}

const reviewStatuses = new Set(['marked_safe', 'confirmed_threat', 'archived'])

export async function reviewBlockedThreat(req, res, next) {
  try {
    const { status } = req.body
    if (!reviewStatuses.has(status)) {
      return res.status(400).json({ error: 'invalid review status' })
    }

    const db = await dbPromise
    await db.run(
      'UPDATE blocked_threats SET review_status = ?, active_visible = ?, reviewed_at = ? WHERE id = ?',
      status,
      status === 'archived' ? 0 : 1,
      new Date().toISOString(),
      req.params.id,
    )
    res.json({ ok: true })
  } catch (error) {
    next(error)
  }
}

export async function clearReviewedThreats(_req, res, next) {
  try {
    const db = await dbPromise
    await db.run(
      "UPDATE blocked_threats SET active_visible = 0 WHERE review_status != 'active'",
    )
    res.json({ ok: true })
  } catch (error) {
    next(error)
  }
}

export async function clearFlaggedThreats(_req, res, next) {
  try {
    const db = await dbPromise
    await db.run('UPDATE blocked_threats SET active_visible = 0')
    res.json({ ok: true })
  } catch (error) {
    next(error)
  }
}

export async function getSystemLogs(_req, res, next) {
  try {
    const db = await dbPromise
    const rows = await db.all('SELECT * FROM system_logs ORDER BY created_at DESC LIMIT 100')
    res.json(
      rows.map((row) => ({
        id: row.id,
        level: row.level,
        event: row.event,
        message: row.message,
        metadata: fromJson(row.metadata, {}),
        timestamp: row.created_at,
      })),
    )
  } catch (error) {
    next(error)
  }
}

export async function getLiveFeed(_req, res, next) {
  try {
    const db = await dbPromise
    await syncLiveMonitorActivity(db)
    const rows = await db.all(`
      SELECT * FROM live_monitor_activity
      WHERE history_visible = 1
      ORDER BY created_at DESC
      LIMIT 50
    `)
    res.json(
      rows.map((row) => ({
        id: row.scan_id,
        activityType: row.activity_type,
        source:
          row.source === 'browser-extension'
            ? 'browser-extension'
            : row.activity_type === 'Email'
              ? 'email-background-analyzer'
              : row.source,
        target: row.target,
        domain: row.domain,
        title: row.title,
        detail: row.detail,
        score: row.score,
        status: row.status,
        riskStatus: row.risk_status,
        timestamp: row.created_at,
        warningSigns: fromJson(row.warning_signs),
      })),
    )
  } catch (error) {
    next(error)
  }
}

export async function getStats(_req, res, next) {
  try {
    const db = await dbPromise
    const [total, blocked, clean, unread] = await Promise.all([
      db.get('SELECT COUNT(*) AS count FROM scans WHERE history_visible = 1'),
      db.get('SELECT COUNT(*) AS count FROM blocked_threats WHERE active_visible = 1'),
      db.get("SELECT COUNT(*) AS count FROM scans WHERE status = 'Safe' AND history_visible = 1"),
      db.get("SELECT COUNT(*) AS count FROM alerts WHERE status = 'new'"),
    ])
    res.json({
      total: total.count,
      blocked: blocked.count,
      clean: clean.count,
      unreadAlerts: unread.count,
      liveScanCount: total.count,
      systemActive: true,
    })
  } catch (error) {
    next(error)
  }
}
