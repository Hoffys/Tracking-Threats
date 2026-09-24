import crypto from 'node:crypto'
import { dbPromise } from '../db/database.js'

const publicDeployment = () => process.env.PUBLIC_DEPLOYMENT === 'true'
const clientIdPattern = /^cl_[a-f0-9]{32}$/

export async function createClientCredential() {
  const clientId = `cl_${crypto.randomBytes(16).toString('hex')}`
  const token = crypto.randomBytes(32).toString('base64url')
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex')
  const db = await dbPromise
  await db.run(
    'INSERT INTO client_credentials (client_id, token_hash, created_at, last_seen_at) VALUES (?, ?, ?, ?)',
    clientId,
    tokenHash,
    new Date().toISOString(),
    new Date().toISOString(),
  )
  return { clientId, token }
}

export async function requireClient(req, res, next) {
  if (!publicDeployment()) return next()

  const clientId = req.params.clientId ?? req.body?.clientId ?? req.query?.clientId
  const token = req.get('x-client-token') ?? ''
  if (!clientIdPattern.test(String(clientId ?? '')) || !/^[A-Za-z0-9_-]{40,80}$/.test(token)) {
    return res.status(401).json({ error: 'Client access is required' })
  }

  try {
    const db = await dbPromise
    const row = await db.get(
      'SELECT token_hash FROM client_credentials WHERE client_id = ?',
      clientId,
    )
    const candidate = crypto.createHash('sha256').update(token).digest()
    const expected = Buffer.from(row?.token_hash ?? '0'.repeat(64), 'hex')
    if (!crypto.timingSafeEqual(candidate, expected) || !row) {
      return res.status(403).json({ error: 'Client access denied', code: 'CLIENT_ACCESS_DENIED' })
    }
    req.clientId = clientId
    await db.run('UPDATE client_credentials SET last_seen_at = ? WHERE client_id = ? AND (last_seen_at IS NULL OR last_seen_at < ?)',
      new Date().toISOString(), clientId, new Date(Date.now() - 60 * 1000).toISOString())
    return next()
  } catch (error) {
    return next(error)
  }
}

export function requireClientForScan(req, res, next) {
  if (req.body?.preview === true && req.path === '/scan/url') return next()
  return requireClient(req, res, next)
}
