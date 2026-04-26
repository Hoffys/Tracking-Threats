import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ThreatContext } from './ThreatContext'
import { apiService } from '../services/api'

const emptyStats = {
  blocked: 0,
  clean: 0,
  total: 0,
  unreadAlerts: 0,
}

const defaultNotificationSettings = {
  reportEmails: [],
  emailScanReports: true,
  emailHistoryDigest: true,
}

const readNotificationSettings = () => {
  try {
    const stored = localStorage.getItem('threattrack:notification-settings')
    return stored
      ? { ...defaultNotificationSettings, ...JSON.parse(stored) }
      : defaultNotificationSettings
  } catch {
    return defaultNotificationSettings
  }
}

export function ThreatProvider({ children }) {
  const [scanHistory, setScanHistory] = useState([])
  const [alerts, setAlerts] = useState([])
  const [flaggedThreats, setFlaggedThreats] = useState([])
  const [threatAuditLogs, setThreatAuditLogs] = useState([])
  const [activeNotification, setActiveNotification] = useState(null)
  const [liveFeed, setLiveFeed] = useState([])
  const [liveScanCount, setLiveScanCount] = useState(0)
  const [systemLogs, setSystemLogs] = useState([])
  const [systemActive, setSystemActive] = useState(false)
  const [stats, setStats] = useState(emptyStats)
  const [notificationSettings, setNotificationSettings] = useState(readNotificationSettings)
  const [darkMode, setDarkMode] = useState(() => {
    try {
      const stored = localStorage.getItem('threattrack:dark-mode')
      return stored ? JSON.parse(stored) : true
    } catch {
      return true
    }
  })
  const latestDangerousAlertId = useRef(null)

  const refreshData = useCallback(async () => {
    const [scans, nextAlerts, blockedThreats, auditLogs, feed, logs, nextStats] = await Promise.all([
      apiService.getHistory(),
      apiService.getAlerts(),
      apiService.getBlockedThreats(),
      apiService.getThreatAuditLogs(),
      apiService.getLiveFeed(),
      apiService.getSystemLogs(),
      apiService.getStats(),
    ])

    setScanHistory(scans)
    setAlerts(nextAlerts)
    setFlaggedThreats(blockedThreats)
    setThreatAuditLogs(auditLogs)
    setLiveFeed(feed)
    setSystemLogs(logs)
    setLiveScanCount(nextStats.liveScanCount ?? nextStats.total ?? 0)
    setSystemActive(Boolean(nextStats.systemActive))
    setStats({
      blocked: nextStats.blocked,
      clean: nextStats.clean,
      total: nextStats.total,
      unreadAlerts: nextStats.unreadAlerts,
    })

    const dangerousAlert = nextAlerts.find(
      (alert) => alert.status === 'new' && alert.riskLevel === 'Dangerous',
    )
    if (dangerousAlert && dangerousAlert.id !== latestDangerousAlertId.current) {
      latestDangerousAlertId.current = dangerousAlert.id
      setActiveNotification(dangerousAlert)
    }
  }, [])

  useEffect(() => {
    localStorage.setItem('threattrack:dark-mode', JSON.stringify(darkMode))
    document.documentElement.classList.toggle('dark', darkMode)
  }, [darkMode])

  useEffect(() => {
    localStorage.setItem(
      'threattrack:notification-settings',
      JSON.stringify(notificationSettings),
    )
  }, [notificationSettings])

  useEffect(() => {
    const refreshTimeoutId = window.setTimeout(() => {
      refreshData().catch(console.error)
    }, 0)
    const intervalId = window.setInterval(() => {
      refreshData().catch(console.error)
    }, 2000)

    return () => {
      window.clearTimeout(refreshTimeoutId)
      window.clearInterval(intervalId)
    }
  }, [refreshData])

  const createScan = useCallback(
    async ({ type, target, content = '' }) => {
      const scan =
        type === 'URL' || type === 'Domain'
          ? await apiService.scanUrl(target)
          : type === 'Email'
            ? await apiService.scanEmail({
                sender: target,
                subject: content.split('\n')[0] ?? '',
                body: content.split('\n').slice(1).join('\n') || content,
              })
            : await apiService.scanMessage({ target, content })

      refreshData().catch(console.error)
      if (scan.status === 'Dangerous') {
        setActiveNotification({
          id: scan.id,
          source: scan.target,
          threatType: scan.type,
          riskLevel: scan.status,
          recommendedAction: scan.recommendations?.[0] ?? scan.recommendation,
        })
      }
      return scan
    },
    [refreshData],
  )

  const clearHistory = useCallback(async () => {
    await apiService.clearHistory()
    await apiService.clearThreatAuditLogs()
    await refreshData()
  }, [refreshData])

  const acknowledgeAlert = useCallback(
    async (id) => {
      await apiService.dismissAlert(id)
      await refreshData()
    },
    [refreshData],
  )

  const reviewThreat = useCallback(
    async (id, status) => {
      await apiService.reviewBlockedThreat(id, status)
      await refreshData()
    },
    [refreshData],
  )

  const clearReviewedThreats = useCallback(async () => {
    await apiService.clearReviewedThreats()
    await refreshData()
  }, [refreshData])

  const dismissNotification = () => setActiveNotification(null)
  const autoBlock = () => null

  const value = useMemo(
    () => ({
      activeNotification,
      alerts,
      acknowledgeAlert,
      autoBlock,
      clearHistory,
      clearReviewedThreats,
      createScan,
      darkMode,
      dismissNotification,
      flaggedThreats,
      liveEvents: liveFeed,
      liveFeed,
      liveScanCount,
      notificationSettings,
      scanHistory,
      setDarkMode,
      setNotificationSettings,
      stats,
      systemLogs,
      systemActive,
      reviewThreat,
      threatAuditLogs,
    }),
    [
      activeNotification,
      acknowledgeAlert,
      clearHistory,
      clearReviewedThreats,
      createScan,
      darkMode,
      flaggedThreats,
      liveFeed,
      liveScanCount,
      notificationSettings,
      scanHistory,
      stats,
      systemLogs,
      systemActive,
      alerts,
      reviewThreat,
      threatAuditLogs,
    ],
  )

  return <ThreatContext.Provider value={value}>{children}</ThreatContext.Provider>
}
