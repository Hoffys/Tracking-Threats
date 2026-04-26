import { Router } from 'express'
import {
  clearHistory,
  clearReviewedThreats,
  clearThreatAuditLogs,
  dismissAlert,
  getAlerts,
  getBlockedThreats,
  getHistory,
  getLiveFeed,
  getStats,
  getSystemLogs,
  getThreatAuditLogs,
  reviewBlockedThreat,
} from '../controllers/dataController.js'

export const dataRoutes = Router()

dataRoutes.get('/history', getHistory)
dataRoutes.delete('/history', clearHistory)
dataRoutes.get('/alerts', getAlerts)
dataRoutes.patch('/alerts/:id/dismiss', dismissAlert)
dataRoutes.get('/blocked-threats', getBlockedThreats)
dataRoutes.get('/threat-audit-logs', getThreatAuditLogs)
dataRoutes.patch('/threat-audit-logs/clear', clearThreatAuditLogs)
dataRoutes.patch('/blocked-threats/:id/review', reviewBlockedThreat)
dataRoutes.patch('/blocked-threats/clear-reviewed', clearReviewedThreats)
dataRoutes.get('/system-logs', getSystemLogs)
dataRoutes.get('/live-feed', getLiveFeed)
dataRoutes.get('/stats', getStats)
