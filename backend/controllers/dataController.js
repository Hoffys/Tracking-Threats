import { dbPromise, fromJson } from '../db/database.js'
import { mapAlert, mapBlockedThreat, mapScan } from './scanController.js'
import { getDomain } from '../services/urlScanner.js'

export async function getHistory(_req, res, next) {
  try {
    const db = await dbPromise
    const rows = await db.all('SELECT * FROM scans ORDER BY created_at DESC LIMIT 250')
    res.json(rows.map(mapScan))
  } catch (error) {
    next(error)
  }
}

export async function clearHistory(_req, res, next) {
  try {
    const db = await dbPromise
    await db.run('DELETE FROM scans')
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

export async function getBlockedThreats(_req, res, next) {
  try {
    const db = await dbPromise
    const rows = await db.all('SELECT * FROM blocked_threats ORDER BY created_at DESC LIMIT 250')
    res.json(rows.map(mapBlockedThreat))
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
    const rows = await db.all('SELECT * FROM scans ORDER BY created_at DESC LIMIT 50')
    res.json(
      rows.map((row) => {
        const scan = mapScan(row)
        return {
          id: scan.id,
          activityType: scan.type === 'Email' ? 'Email' : scan.type,
          source:
            scan.source === 'browser-extension'
              ? 'browser-extension'
              : scan.type === 'Email'
                ? 'email-background-analyzer'
                : scan.source,
          target: scan.target,
          domain: scan.type === 'URL' ? getDomain(scan.target) : scan.target,
          title: scan.source === 'browser-extension' ? 'Browser URL scan' : `${scan.type} scan`,
          detail: scan.content || scan.target,
          score: scan.score,
          status: scan.status === 'Dangerous' ? 'Blocked' : scan.status,
          riskStatus: scan.status,
          timestamp: scan.date,
          warningSigns: scan.warningSigns,
        }
      }),
    )
  } catch (error) {
    next(error)
  }
}

export async function getStats(_req, res, next) {
  try {
    const db = await dbPromise
    const [total, blocked, clean, unread] = await Promise.all([
      db.get('SELECT COUNT(*) AS count FROM scans'),
      db.get('SELECT COUNT(*) AS count FROM blocked_threats'),
      db.get("SELECT COUNT(*) AS count FROM scans WHERE status = 'Safe'"),
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
