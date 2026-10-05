import crypto from 'node:crypto'
import { Router } from 'express'
import rateLimit from 'express-rate-limit'
import { dbPromise } from '../db/database.js'
import { requireAdminStrict } from '../middleware/adminAuth.js'
import { deleteClientScanData } from '../services/scanRepository.js'
import { mapAnnouncementRow, validateAnnouncementInput } from '../services/announcementService.js'
import { evaluationRoutes } from './evaluationRoutes.js'

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

adminRoutes.use('/evaluations', evaluationRoutes)

adminRoutes.get('/announcements', async (_req, res, next) => {
  try {
    const db = await dbPromise
    const rows = await db.all('SELECT * FROM announcements ORDER BY created_at DESC')
    res.json(rows.map(mapAnnouncementRow))
  } catch (error) {
    next(error)
  }
})

adminRoutes.post('/announcements', async (req, res, next) => {
  try {
    const input = validateAnnouncementInput(req.body)
    const db = await dbPromise
    const now = new Date().toISOString()
    const id = `an_${crypto.randomBytes(16).toString('hex')}`
    const publishedAt = input.isActive ? now : null
    await db.run(
      `INSERT INTO announcements
        (id, type, title, message, priority, target_version, is_active,
         published_at, expires_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      id,
      input.type,
      input.title,
      input.message,
      input.priority,
      input.targetVersion,
      input.isActive ? 1 : 0,
      publishedAt,
      input.expiresAt,
      now,
      now,
    )
    const row = await db.get('SELECT * FROM announcements WHERE id = ?', id)
    res.status(201).json(mapAnnouncementRow(row))
  } catch (error) {
    next(error)
  }
})

adminRoutes.patch('/announcements/:announcementId', async (req, res, next) => {
  try {
    const announcementId = String(req.params.announcementId ?? '')
    if (!/^an_[a-f0-9]{32}$/.test(announcementId)) {
      return res.status(400).json({ error: 'Invalid announcement ID' })
    }
    const db = await dbPromise
    const existing = await db.get('SELECT * FROM announcements WHERE id = ?', announcementId)
    if (!existing) return res.status(404).json({ error: 'Announcement not found' })
    const input = validateAnnouncementInput(req.body, { partial: true })
    if (Object.keys(input).length === 0) {
      return res.status(400).json({ error: 'No announcement changes supplied' })
    }
    const merged = {
      type: input.type ?? existing.type,
      title: input.title ?? existing.title,
      message: input.message ?? existing.message,
      priority: input.priority ?? existing.priority,
      targetVersion: Object.hasOwn(input, 'targetVersion') ? input.targetVersion : existing.target_version,
      expiresAt: Object.hasOwn(input, 'expiresAt') ? input.expiresAt : existing.expires_at,
      isActive: Object.hasOwn(input, 'isActive') ? input.isActive : Boolean(existing.is_active),
    }
    if (merged.type === 'update' && !merged.targetVersion) {
      return res.status(400).json({ error: 'Extension updates require a target version' })
    }
    const now = new Date().toISOString()
    const publishedAt = merged.isActive ? (existing.published_at ?? now) : existing.published_at
    await db.run(
      `UPDATE announcements SET
        type = ?, title = ?, message = ?, priority = ?, target_version = ?,
        is_active = ?, published_at = ?, expires_at = ?, updated_at = ?
       WHERE id = ?`,
      merged.type,
      merged.title,
      merged.message,
      merged.priority,
      merged.targetVersion,
      merged.isActive ? 1 : 0,
      publishedAt,
      merged.expiresAt,
      now,
      announcementId,
    )
    const row = await db.get('SELECT * FROM announcements WHERE id = ?', announcementId)
    res.json(mapAnnouncementRow(row))
  } catch (error) {
    next(error)
  }
})

adminRoutes.delete('/announcements/:announcementId', async (req, res, next) => {
  try {
    const announcementId = String(req.params.announcementId ?? '')
    if (!/^an_[a-f0-9]{32}$/.test(announcementId)) {
      return res.status(400).json({ error: 'Invalid announcement ID' })
    }
    const db = await dbPromise
    const existing = await db.get('SELECT id FROM announcements WHERE id = ?', announcementId)
    if (!existing) return res.status(404).json({ error: 'Announcement not found' })
    await db.run('DELETE FROM announcements WHERE id = ?', announcementId)
    res.json({ ok: true, id: announcementId })
  } catch (error) {
    next(error)
  }
})

adminRoutes.get('/overview', async (_req, res, next) => {
  try {
    const db = await dbPromise
    const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
    const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()
    const [clients, scans, recentScans, byType, byStatus, downloads, usage, deviceRows] = await Promise.all([
      db.get('SELECT COUNT(*) AS count FROM client_credentials'),
      db.get('SELECT COUNT(*) AS count FROM scans'),
      db.get("SELECT COUNT(*) AS count FROM scans WHERE created_at >= ?", new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()),
      db.all('SELECT type, COUNT(*) AS count FROM scans GROUP BY type ORDER BY count DESC'),
      db.all('SELECT status, COUNT(*) AS count FROM scans GROUP BY status ORDER BY count DESC'),
      db.get("SELECT count, started_at FROM usage_counters WHERE name = 'extension-downloads'"),
      db.get(`SELECT
        COUNT(CASE WHEN extension_seen_at IS NOT NULL THEN 1 END) AS extensions,
        COUNT(CASE WHEN extension_seen_at >= ? THEN 1 END) AS extensions_day,
        COUNT(CASE WHEN extension_seen_at >= ? THEN 1 END) AS extensions_week,

        COUNT(DISTINCT device_id) AS devices,
        COUNT(DISTINCT CASE
          WHEN last_seen_at >= ? THEN device_id
        END) AS devices_day,
        COUNT(DISTINCT CASE 
          WHEN last_seen_at >= ? THEN device_id
        END) AS devices_week,

        COUNT(CASE WHEN last_seen_at >= ? THEN 1 END) AS clients_day,
        COUNT(CASE WHEN last_seen_at >= ? THEN 1 END) AS clients_week

        FROM client_credentials`,
        dayAgo,
        weekAgo,
        dayAgo,
        weekAgo,
        dayAgo,
        weekAgo
      ),
      db.all(`
        SELECT
        d.device_id,
        d.device_name,
        d.created_at,
        d.last_seen_at,
        c.client_id,
        c.browser_name
      FROM devices d
      LEFT JOIN client_credentials c
       ON c.device_id = d.device_id
      ORDER BY d.created_at DESC
        `),
    ])


    const deviceGroupMap = new Map()

for (const row of deviceRows) {
  if (!deviceGroupMap.has(row.device_id)) {
    deviceGroupMap.set(row.device_id, {
      device_id: row.device_id,
      device_name: row.device_name,
      created_at: row.created_at,
      last_seen_at: row.last_seen_at,
      extension_count: 0,
      browsers: [],
    })
  }

  const device = deviceGroupMap.get(row.device_id)

  if (row.client_id) {
    device.extension_count += 1
  }

  if (
    row.browser_name &&
    !device.browsers.includes(row.browser_name)
  ) {
    device.browsers.push(row.browser_name)
  }
}

const deviceGroups = [...deviceGroupMap.values()].map((device) => ({
  ...device,
  browsers: device.browsers.join(','),
}))
     
    res.json({
      clients: clients.count,
      scans: scans.count,
      scansLast24Hours: recentScans.count,
      byType,
      byStatus,
      usage: {
        extensionDownloads: downloads?.count ?? 0,
        trackingStartedAt: downloads?.started_at ?? null,

        registeredExtensions: usage.extensions,
        activeExtensions24h: usage.extensions_day,
        activeExtensions7d: usage.extensions_week,

        registeredDevices: usage.devices,
        activeDevices24h: usage.devices_day,
        activeDevices7d: usage.devices_week,

        activeClients24h: usage.clients_day,
        activeClients7d: usage.clients_week,
      },
      deviceGroups,
    })
  } catch (error) {
    next(error)
  }
})

adminRoutes.get('/clients', async (_req, res, next) => {
  try {
    const db = await dbPromise
    const [registered, activity] = await Promise.all([
      db.all(`
        SELECT
          c.client_id,
          c.created_at,
          c.last_seen_at,
          c.extension_seen_at,
          c.extension_version,
          c.device_id,
          c.browser_name,
          d.device_name
        FROM client_credentials c
        LEFT JOIN devices d
          ON d.device_id = c.device_id
        ORDER BY COALESCE(c.last_seen_at, c.created_at) DESC
        LIMIT 100
      `),
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
        lastSeenAt: row.last_seen_at,
        extensionLastSeenAt: row.extension_seen_at,
        extensionVersion: row.extension_version,

        deviceId: row.device_id,
        deviceName: row.device_name,
        browserName: row.browser_name,
        scanCount: 0,
        
        lastScanAt: null,
        accessStatus: 'active',
      }]),
    )
    activity.forEach((row) => {
      const previous = clients.get(row.client_id)
      clients.set(row.client_id, {
        ...previous,
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
