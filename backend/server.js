import cors from 'cors'
import express from 'express'
import { initDatabase } from './db/database.js'
import { dataRoutes } from './routes/dataRoutes.js'
import { scanRoutes } from './routes/scanRoutes.js'
import { startAutoMonitor } from './services/autoMonitor.js'

const app = express()
const port = process.env.PORT ?? 4000

app.use(cors())
app.use(express.json({ limit: '1mb' }))

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, systemActive: true })
})

app.use('/api', scanRoutes)
app.use('/api', dataRoutes)

app.use((error, _req, res, _next) => {
  void _next
  console.error(error)
  res.status(500).json({ error: 'Internal server error' })
})

await initDatabase()

if (process.env.AUTO_MONITOR === 'true') {
  startAutoMonitor()
}

app.listen(port, () => {
  console.log(`ThreatTrack backend running at http://localhost:${port}`)
  console.log(
    `Auto monitor ${process.env.AUTO_MONITOR === 'true' ? 'enabled' : 'disabled'}`,
  )
})
