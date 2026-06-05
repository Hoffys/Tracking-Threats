import { Router } from 'express'
import {
  clearHistory,
  clearAlerts,
  clearFlaggedThreats,
  clearReviewedThreats,
  clearThreatAuditLogs,
  dismissAlert,
  emailHistoryDigest,
  getAlerts,
  getBlockedThreats,
  getHistory,
  getLiveFeed,
  getNotificationSettings,
  getSafeHosts,
  getStats,
  getSystemLogs,
  getThreatAuditLogs,
  reviewBlockedThreat,
  saveNotificationSettings,
} from '../controllers/dataController.js'

export const dataRoutes = Router()

dataRoutes.get('/history', getHistory)
dataRoutes.delete('/history', clearHistory)
dataRoutes.get('/alerts', getAlerts)
dataRoutes.delete('/alerts', clearAlerts)
dataRoutes.patch('/alerts/:id/dismiss', dismissAlert)
dataRoutes.get('/blocked-threats', getBlockedThreats)
dataRoutes.get('/safe-hosts', getSafeHosts)
dataRoutes.get('/threat-audit-logs', getThreatAuditLogs)
dataRoutes.patch('/threat-audit-logs/clear', clearThreatAuditLogs)
dataRoutes.patch('/blocked-threats/:id/review', reviewBlockedThreat)
dataRoutes.patch('/blocked-threats/clear-active', clearFlaggedThreats)
dataRoutes.patch('/blocked-threats/clear-reviewed', clearReviewedThreats)
dataRoutes.get('/system-logs', getSystemLogs)
dataRoutes.get('/live-feed', getLiveFeed)
dataRoutes.get('/stats', getStats)
dataRoutes.get('/notification-settings', getNotificationSettings)
dataRoutes.put('/notification-settings', saveNotificationSettings)
dataRoutes.post('/notification-settings/history-digest', emailHistoryDigest)
