import crypto from 'node:crypto'
import { Router } from 'express'
import rateLimit from 'express-rate-limit'
import { createClientCredential, requireClient } from '../middleware/clientAuth.js'
import { dbPromise } from '../db/database.js'
import { getExtensionPackage } from '../services/extensionPackage.js'

export const clientRoutes = Router()

const PAIR_CODE_TTL_MS = 10 * 60 * 1000

const createDeviceId = () =>
  `dev_${crypto.randomBytes(16).toString('hex')}`

const createPairCode = () =>
  crypto.randomBytes(4).toString('hex').toUpperCase()

const hashPairCode = (code) =>
  crypto
    .createHash('sha256')
    .update(String(code).trim().toUpperCase())
    .digest('hex')

const issuePairCode = async (db, deviceId) => {
  const now = new Date()
  const expiresAt = new Date(now.getTime() + PAIR_CODE_TTL_MS)
  const pairCode = createPairCode()

  await db.run(
    'DELETE FROM device_pair_codes WHERE expires_at <= ?',
    now.toISOString(),
  )

  await db.run(
    `INSERT INTO device_pair_codes
      (code_hash, device_id, expires_at, created_at)
      VALUES (?, ?, ?, ?)`,
    hashPairCode(pairCode),
    deviceId,
    expiresAt.toISOString(),
    now.toISOString(),
  )

  return {
    pairCode,
    expiresAt: expiresAt.toISOString(),
  }
}

clientRoutes.get('/public/extension/download', rateLimit({ windowMs: 15 * 60 * 1000, limit: 20 }), async (req, res, next) => {
  try {
    const archive = await getExtensionPackage()
    if (req.method === 'GET') {
      const db = await dbPromise
      await db.run("UPDATE usage_counters SET count = count + 1 WHERE name = 'extension-downloads'")
    }
    res.set('Cache-Control', 'no-store')
      .attachment('tracking-threats-extension.zip').send(archive)
  } catch (error) { next(error) }
})

clientRoutes.post('/public/extension/heartbeat', requireClient, async (req, res, next) => {
  if (!req.clientId) return res.status(401).json({ error: 'Client access is required' })
  const version = String(req.body?.version ?? '')
  if (!/^\d{1,5}\.\d{1,5}\.\d{1,5}(\.\d{1,5})?$/.test(version)) {
    return res.status(400).json({ error: 'Invalid extension version' })
  }
  try {
    const db = await dbPromise
    await db.run('UPDATE client_credentials SET extension_seen_at = ?, extension_version = ? WHERE client_id = ?',
      new Date().toISOString(), version, req.clientId)
    res.json({ ok: true })
  } catch (error) { next(error) }
})

clientRoutes.post('/public/devices', requireClient, async (req, res, next) => {
  if (!req.clientId) {
    return res.status(401).json({
      error: 'Client access is required',
    })
  }

  const deviceName = String(req.body?.deviceName ?? '').trim()

  if (!deviceName || deviceName.length > 80) {
    return res.status(400).json({
      error: 'Device name must be between 1 and 80 characters',
    })
  }

  try {
    const db = await dbPromise

    const existingClient = await db.get(
      `SELECT
        c.device_id,
        d.device_name
      FROM client_credentials c
      LEFT JOIN devices d
        ON d.device_id = c.device_id
      WHERE c.client_id = ?`,
      req.clientId,
    )

    let deviceId = existingClient?.device_id
    let finalDeviceName = existingClient?.device_name

    if (!deviceId) {
      deviceId = createDeviceId()
      finalDeviceName = deviceName

      const now = new Date().toISOString()

      await db.transaction(async (tx) => {
        await tx.run(
          `INSERT INTO devices
            (device_id, device_name, created_at, last_seen_at)
            VALUES (?, ?, ?, ?)`,
          deviceId,
          deviceName,
          now,
          now,
        )

        await tx.run(
          `UPDATE client_credentials
          SET device_id = ?
          WHERE client_id = ?`,
          deviceId,
          req.clientId,
        )
      })
    }

    const pairing = await issuePairCode(db, deviceId)

    return res.status(201).json({
      ok: true,
      device: {
        deviceId,
        deviceName: finalDeviceName,
      },
      pairCode: pairing.pairCode,
      expiresAt: pairing.expiresAt,
    })
  } catch (error) {
    next(error)
  }
})


clientRoutes.post('/public/devices/pair-code', requireClient, async (req, res, next) => {
  if (!req.clientId) {
    return res.status(401).json({
      error: 'Client access is required',
    })
  }

  try {
    const db = await dbPromise

    const client = await db.get(
      `SELECT device_id
      FROM client_credentials
      WHERE client_id = ?`,
      req.clientId,
    )

    if (!client?.device_id) {
      return res.status(409).json({
        error: 'This extension is not linked to a device yet',
      })
    }

    const pairing = await issuePairCode(db, client.device_id)

    return res.json({
      ok: true,
      deviceId: client.device_id,
      pairCode: pairing.pairCode,
      expiresAt: pairing.expiresAt,
    })
  } catch (error) {
    next(error)
  }
})


clientRoutes.post('/public/devices/pair', requireClient, async (req, res, next) => {
  if (!req.clientId) {
    return res.status(401).json({
      error: 'Client access is required',
    })
  }

  const pairCode = String(req.body?.pairCode ?? '')
    .trim()
    .toUpperCase()

  const browserName = String(req.body?.browserName ?? '')
    .trim()

  if (!/^[A-F0-9]{8}$/.test(pairCode)) {
    return res.status(400).json({
      error: 'Invalid pairing code',
    })
  }

  const allowedBrowsers = new Set([
    'Chrome',
    'Edge',
    'Brave',
    'Other',
  ])

  const finalBrowserName = allowedBrowsers.has(browserName)
    ? browserName
    : 'Other'

  try {
    const db = await dbPromise
    const now = new Date().toISOString()

    const pairing = await db.get(
      `SELECT
        p.device_id,
        p.expires_at,
        d.device_name
      FROM device_pair_codes p
      JOIN devices d
        ON d.device_id = p.device_id
      WHERE p.code_hash = ?`,
      hashPairCode(pairCode),
    )

    if (!pairing) {
      return res.status(400).json({
        error: 'Pairing code was not found',
      })
    }

    if (new Date(pairing.expires_at).getTime() <= Date.now()) {
      return res.status(400).json({
        error: 'Pairing code has expired',
      })
    }

    await db.transaction(async (tx) => {
      await tx.run(
        `UPDATE client_credentials
        SET
          device_id = ?,
          browser_name = ?
        WHERE client_id = ?`,
        pairing.device_id,
        finalBrowserName,
        req.clientId,
      )

      await tx.run(
        `UPDATE devices
        SET last_seen_at = ?
        WHERE device_id = ?`,
        now,
        pairing.device_id,
      )
    })

    return res.json({
      ok: true,
      device: {
        deviceId: pairing.device_id,
        deviceName: pairing.device_name,
      },
      browserName: finalBrowserName,
    })
  } catch (error) {
    next(error)
  }
})

clientRoutes.get('/public/clients/:clientId', requireClient, (req, res) => {
  res.set('Cache-Control', 'no-store').json({ clientId: req.params.clientId })
})

clientRoutes.post(
  '/public/clients',
  rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 20,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
  }),
  async (_req, res, next) => {
    try {
      res.status(201).json(await createClientCredential())
    } catch (error) {
      next(error)
    }
  },
)
