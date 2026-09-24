import { Router } from 'express'
import rateLimit from 'express-rate-limit'
import { createClientCredential, requireClient } from '../middleware/clientAuth.js'
import { dbPromise } from '../db/database.js'
import { getExtensionPackage } from '../services/extensionPackage.js'

export const clientRoutes = Router()

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
