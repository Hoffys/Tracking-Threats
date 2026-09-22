import path from 'node:path'
import { fileURLToPath } from 'node:url'
import './config/loadEnv.js'
import cors from 'cors'
import express from 'express'
import rateLimit from 'express-rate-limit'
import helmet from 'helmet'
import { databaseProvider, initDatabase } from './db/database.js'
import { dataRoutes } from './routes/dataRoutes.js'
import { adminRoutes } from './routes/adminRoutes.js'
import { clientRoutes } from './routes/clientRoutes.js'
import { scanRoutes } from './routes/scanRoutes.js'
import { startAutoMonitor } from './services/autoMonitor.js'
import { purgeExpiredData } from './services/scanRepository.js'

const app = express()
const port = process.env.PORT ?? 4000
const __dirname = path.dirname(fileURLToPath(import.meta.url))
const distPath = path.resolve(__dirname, '..', 'dist')

const parseInteger = (value, fallback) => {
  const parsed = Number.parseInt(value, 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

const allowedOrigins = new Set(
  [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    process.env.FRONTEND_ORIGIN,
    process.env.RAILWAY_PUBLIC_DOMAIN
      ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
      : '',
    ...(process.env.CORS_ORIGINS ?? '').split(','),
  ]
    .map((origin) => origin?.trim())
    .filter(Boolean),
)

const allowChromeExtensions = process.env.CORS_ALLOW_CHROME_EXTENSIONS === 'true'
const allowRequestsWithoutOrigin = process.env.CORS_ALLOW_NO_ORIGIN !== 'false'

const corsOptions = {
  origin(origin, callback) {
    if (!origin && allowRequestsWithoutOrigin) return callback(null, true)
    if (origin && allowedOrigins.has(origin)) return callback(null, true)
    if (origin?.startsWith('chrome-extension://') && allowChromeExtensions) {
      return callback(null, true)
    }
    const error = new Error('Origin is not allowed by CORS')
    error.statusCode = 403
    return callback(error)
  },
}

app.disable('x-powered-by')
app.set('trust proxy', 1)
app.use(helmet())
app.use('/api', cors(corsOptions))
app.use(express.json({ limit: process.env.JSON_BODY_LIMIT ?? '512kb' }))
app.use('/api', (_req, res, next) => {
  res.set('Cache-Control', 'no-store')
  next()
})
app.use(
  '/api',
  rateLimit({
    windowMs: parseInteger(process.env.API_RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000),
    limit: parseInteger(process.env.API_RATE_LIMIT_MAX, 1500),
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: {
      error: 'Too many API requests. Please wait a moment and try again.',
      code: 'RATE_LIMITED',
    },
  }),
)
app.use(
  '/api/scan',
  rateLimit({
    windowMs: parseInteger(process.env.SCAN_RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000),
    limit: parseInteger(process.env.SCAN_RATE_LIMIT_MAX, 900),
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: {
      error: 'Too many scan requests. Please wait a moment and try again.',
      code: 'SCAN_RATE_LIMITED',
    },
  }),
)

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, systemActive: true, repository: databaseProvider })
})

app.use('/api', clientRoutes)
app.use('/api', scanRoutes)
app.use('/api/admin', adminRoutes)
app.use('/api', dataRoutes)

if (process.env.NODE_ENV === 'production') {
  app.use(express.static(distPath))
  app.get(/^(?!\/api).*/, (_req, res) => {
    res.sendFile(path.join(distPath, 'index.html'))
  })
}

app.use((error, _req, res, _next) => {
  void _next
  const statusCode = error.statusCode ?? 500
  if (statusCode >= 500) console.error(error)
  res.status(statusCode).json({
    error: statusCode >= 500 ? 'Internal server error' : error.message,
  })
})

await initDatabase()
await purgeExpiredData()

const retentionInterval = setInterval(
  () => purgeExpiredData().catch((error) => console.error('Retention cleanup failed', error)),
  6 * 60 * 60 * 1000,
)
retentionInterval.unref()

if (process.env.AUTO_MONITOR === 'true') {
  startAutoMonitor()
}

app.listen(port, () => {
  console.log(`Tracking Threats backend running at http://localhost:${port}`)
  console.log(`Scan repository: ${databaseProvider}`)
  console.log(
    `Auto monitor ${process.env.AUTO_MONITOR === 'true' ? 'enabled' : 'disabled'}`,
  )
})
