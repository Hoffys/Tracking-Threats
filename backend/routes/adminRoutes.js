import { Router } from 'express'
import rateLimit from 'express-rate-limit'
import { dbPromise } from '../db/database.js'
import { requireAdminStrict } from '../middleware/adminAuth.js'
import { deleteClientScanData } from '../services/scanRepository.js'

export const adminRoutes = Router()

adminRoutes.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 60,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
  }),
  requireAdminStrict,
)

adminRoutes.get('/overview', async (_req, res, next) => {
  try {
    const db = await dbPromise
    const [clients, scans, recentScans, byType, byStatus] = await Promise.all([
      db.get('SELECT COUNT(*) AS count FROM client_credentials'),
      db.get('SELECT COUNT(*) AS count FROM scans'),
      db.get("SELECT COUNT(*) AS count FROM scans WHERE created_at >= ?", new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()),
      db.all('SELECT type, COUNT(*) AS count FROM scans GROUP BY type ORDER BY count DESC'),
      db.all('SELECT status, COUNT(*) AS count FROM scans GROUP BY status ORDER BY count DESC'),
    ])
    res.json({
      clients: clients.count,
      scans: scans.count,
      scansLast24Hours: recentScans.count,
      byType,
      byStatus,
    })
  } catch (error) {
    next(error)
  }
})

adminRoutes.get('/clients', async (_req, res, next) => {
  try {
    const db = await dbPromise
    const [registered, activity] = await Promise.all([
      db.all('SELECT client_id, created_at FROM client_credentials ORDER BY created_at DESC LIMIT 100'),
      db.all(`
        SELECT client_id, COUNT(*) AS scan_count, MAX(created_at) AS last_scan_at
        FROM scans WHERE client_id IS NOT NULL AND client_id != ''
        GROUP BY client_id ORDER BY last_scan_at DESC LIMIT 100
      `),
    ])
    const clients = new Map(
      registered.map((row) => [row.client_id, {
        clientId: row.client_id,
        registeredAt: row.created_at,
        scanCount: 0,
        lastScanAt: null,
        accessStatus: 'active',
      }]),
    )
    activity.forEach((row) => {
      const previous = clients.get(row.client_id)
      clients.set(row.client_id, {
        clientId: row.client_id,
        registeredAt: previous?.registeredAt ?? null,
        scanCount: row.scan_count,
        lastScanAt: row.last_scan_at,
        accessStatus: previous ? 'active' : 'legacy',
      })
    })
    res.json(Array.from(clients.values()).sort((a, b) =>
      String(b.lastScanAt ?? b.registeredAt ?? '').localeCompare(String(a.lastScanAt ?? a.registeredAt ?? '')),
    ).slice(0, 100))
  } catch (error) {
    next(error)
  }
})

adminRoutes.get('/clients/:clientId', async (req, res, next) => {
  try {
    const db = await dbPromise
    const clientId = String(req.params.clientId ?? '')
    if (!/^[a-zA-Z0-9_-]{12,80}$/.test(clientId)) {
      return res.status(400).json({ error: 'Invalid client ID' })
    }
    const [counts, recent] = await Promise.all([
      db.all(
        'SELECT type, status, COUNT(*) AS count FROM scans WHERE client_id = ? GROUP BY type, status',
        clientId,
      ),
      db.all(
        'SELECT id, type, status, score, created_at FROM scans WHERE client_id = ? ORDER BY created_at DESC LIMIT 20',
        clientId,
      ),
    ])
    res.json({ clientId, counts, recent })
  } catch (error) {
    next(error)
  }
})

adminRoutes.get('/logs', async (_req, res, next) => {
  try {
    const db = await dbPromise
    const [system, actions] = await Promise.all([
      db.all('SELECT id, level, event, created_at FROM system_logs ORDER BY created_at DESC LIMIT 80'),
      db.all('SELECT id, action, client_ref, deleted_scans, created_at FROM admin_actions ORDER BY created_at DESC LIMIT 40'),
    ])
    res.json({ system, actions })
  } catch (error) {
    next(error)
  }
})

adminRoutes.delete('/clients/:clientId/data', async (req, res, next) => {
  try {
    const clientId = String(req.params.clientId ?? '')
    if (!/^[a-zA-Z0-9_-]{12,80}$/.test(clientId) || req.body?.confirmClientId !== clientId || req.body?.verifiedRequest !== true) {
      return res.status(400).json({ error: 'Verified request and exact client ID confirmation are required' })
    }
    const db = await dbPromise
    const [credential, scan] = await Promise.all([
      db.get('SELECT client_id FROM client_credentials WHERE client_id = ?', clientId),
      db.get('SELECT id FROM scans WHERE client_id = ? LIMIT 1', clientId),
    ])
    if (!credential && !scan) return res.status(404).json({ error: 'Client not found' })
    res.json({
      ok: true,
      ...(await deleteClientScanData(clientId, { includeSettings: true, adminAction: true })),
    })
  } catch (error) {
    next(error)
  }
})
