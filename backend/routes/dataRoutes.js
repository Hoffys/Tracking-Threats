import { Router } from 'express'
import {
  clearHistory,
  dismissAlert,
  getAlerts,
  getBlockedThreats,
  getHistory,
  getLiveFeed,
  getStats,
  getSystemLogs,
} from '../controllers/dataController.js'

export const dataRoutes = Router()

dataRoutes.get('/history', getHistory)
dataRoutes.delete('/history', clearHistory)
dataRoutes.get('/alerts', getAlerts)
dataRoutes.patch('/alerts/:id/dismiss', dismissAlert)
dataRoutes.get('/blocked-threats', getBlockedThreats)
dataRoutes.get('/system-logs', getSystemLogs)
dataRoutes.get('/live-feed', getLiveFeed)
dataRoutes.get('/stats', getStats)
