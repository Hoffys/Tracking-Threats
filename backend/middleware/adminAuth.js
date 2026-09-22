import crypto from 'node:crypto'

const isPublicDeployment = () => process.env.PUBLIC_DEPLOYMENT === 'true'

const getRequestToken = (req) => {
  const authHeader = req.get('authorization') ?? ''
  if (authHeader.toLowerCase().startsWith('bearer ')) {
    return authHeader.slice(7).trim()
  }

  return req.get('x-admin-token') ?? ''
}

const tokensMatch = (left, right) => {
  const leftBuffer = Buffer.from(left)
  const rightBuffer = Buffer.from(right)
  return (
    leftBuffer.length === rightBuffer.length &&
    crypto.timingSafeEqual(leftBuffer, rightBuffer)
  )
}

export function requireAdminStrict(req, res, next) {
  const adminToken = process.env.ADMIN_API_TOKEN
  if (!adminToken) {
    return res.status(503).json({ error: 'Admin API is disabled' })
  }

  const requestToken = getRequestToken(req)
  if (!requestToken) {
    return res.status(401).json({ error: 'Admin token is required' })
  }

  if (!tokensMatch(requestToken, adminToken)) {
    return res.status(403).json({ error: 'Invalid admin token' })
  }

  return next()
}

export function requireAdmin(req, res, next) {
  if (!isPublicDeployment()) return next()
  return requireAdminStrict(req, res, next)
}
