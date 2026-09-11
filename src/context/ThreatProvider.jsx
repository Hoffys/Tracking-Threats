import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ThreatContext } from './ThreatContext'
import { isPublicDeployment } from '../config/deployment'
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
  mailConfigured: false,
}

const publicScansStorageKey = 'threattrack:public-scans'

const readPublicScans = () => {
  try {
    const stored = localStorage.getItem(publicScansStorageKey)
    return stored ? JSON.parse(stored) : []
  } catch {
    return []
  }
}

const writePublicScans = (scans) => {
  localStorage.setItem(publicScansStorageKey, JSON.stringify(scans.slice(0, 50)))
}

const toPublicScanRecord = (scan) => ({
  id: scan.id ?? crypto.randomUUID(),
  type: scan.type,
  target: scan.target,
  source: 'public-web-scan',
  status: scan.status,
  risk: scan.risk,
  score: scan.score,
  summary: scan.summary,
  responseStatus: scan.responseStatus,
  warningSigns: scan.warningSigns ?? [],
  recommendations: scan.recommendations ?? (scan.recommendation ? [scan.recommendation] : []),
  recommendation: scan.recommendation,
  threatIntel: scan.threatIntel,
  emailBreakdown: scan.emailBreakdown,
  fileDetails: scan.fileDetails
    ? {
        name: scan.fileDetails.name,
        mimeType: scan.fileDetails.mimeType,
        size: scan.fileDetails.size,
        sha256: scan.fileDetails.sha256,
      }
    : undefined,
  blocked: Boolean(scan.blocked),
  date: scan.date ?? new Date().toISOString(),
})

const getDisplayDomain = (target = '') => {
  try {
    return new URL(target.includes('://') ? target : `https://${target}`).hostname
  } catch {
    return target
  }
}

const toPublicLiveEvent = (scan) => ({
  id: scan.id,
  activityType: scan.type,
  source: scan.source ?? 'public-web-scan',
  target: scan.target,
  domain: scan.type === 'URL' ? getDisplayDomain(scan.target) : scan.target,
  title: `${scan.type} scan`,
  detail: scan.summary || scan.target,
  score: scan.score,
  status: scan.status === 'Dangerous' ? 'Blocked' : scan.status,
  riskStatus: scan.status,
  timestamp: scan.date,
  warningSigns: scan.warningSigns ?? [],
})

const toPublicAlert = (scan) => ({
  id: scan.id,
  title: `${scan.type} risk found`,
  source: scan.target,
  time: scan.date,
  severity: scan.status,
  riskLevel: scan.status,
  threatType: scan.type,
  status: 'new',
  message: scan.summary,
  recommendedAction:
    scan.recommendations?.[0] ?? scan.recommendation ?? 'Review before trusting this item.',
})

const getPublicStats = (scans) => {
  const riskyScans = scans.filter((scan) => scan.status === 'Dangerous' || scan.blocked)
  return {
    total: scans.length,
    blocked: riskyScans.length,
    clean: scans.filter((scan) => scan.status === 'Safe').length,
    unreadAlerts: riskyScans.length,
  }
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
  const initialPublicScans = isPublicDeployment ? readPublicScans() : []
  const [scanHistory, setScanHistory] = useState(initialPublicScans)
  const [alerts, setAlerts] = useState(
    isPublicDeployment
      ? initialPublicScans
          .filter((scan) => scan.status === 'Dangerous' || scan.blocked)
          .map(toPublicAlert)
      : [],
  )
  const [flaggedThreats, setFlaggedThreats] = useState([])
  const [threatAuditLogs, setThreatAuditLogs] = useState([])
  const [activeNotification, setActiveNotification] = useState(null)
  const [liveFeed, setLiveFeed] = useState(
    isPublicDeployment ? initialPublicScans.map(toPublicLiveEvent) : [],
  )
  const [liveScanCount, setLiveScanCount] = useState(
    isPublicDeployment ? initialPublicScans.length : 0,
  )
  const [systemLogs, setSystemLogs] = useState([])
  const [systemActive, setSystemActive] = useState(false)
  const [stats, setStats] = useState(
    isPublicDeployment ? getPublicStats(initialPublicScans) : emptyStats,
  )
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

  const applyPublicScans = useCallback((nextScans, health = {}) => {
    const publicAlerts = nextScans
      .filter((scan) => scan.status === 'Dangerous' || scan.blocked)
      .map(toPublicAlert)

    setScanHistory(nextScans)
    setAlerts(publicAlerts)
    setFlaggedThreats([])
    setThreatAuditLogs([])
    setLiveFeed(nextScans.map(toPublicLiveEvent))
    setSystemLogs([])
    setLiveScanCount(nextScans.length)
    setSystemActive(Boolean(health.systemActive ?? true))
    setStats(getPublicStats(nextScans))
  }, [])

  const refreshData = useCallback(async () => {
    if (isPublicDeployment) {
      const health = await apiService.getHealth()
      applyPublicScans(readPublicScans(), health)
      return
    }

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
  }, [applyPublicScans])

  useEffect(() => {
    localStorage.setItem('threattrack:dark-mode', JSON.stringify(darkMode))
    document.documentElement.classList.toggle('dark', darkMode)
  }, [darkMode])

  useEffect(() => {
    if (isPublicDeployment) return

    apiService
      .getNotificationSettings()
      .then((settings) => setNotificationSettings((current) => ({ ...current, ...settings })))
      .catch(console.error)
  }, [])

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
    async ({
      type,
      target,
      content = '',
      fileName,
      mimeType,
      size,
      sha256,
      sender,
      subject,
      body,
    }) => {
      const scan =
        type === 'URL' || type === 'Domain'
          ? await apiService.scanUrl(target)
          : type === 'Email'
            ? await apiService.scanEmail({
                sender: sender ?? target,
                subject: subject ?? content.split('\n')[0] ?? '',
                body: body ?? (content.split('\n').slice(1).join('\n') || content),
              })
            : type === 'File'
              ? await apiService.scanFile({
                  fileName: fileName ?? target,
                  mimeType,
                  size,
                  content,
                  sha256,
                })
              : await apiService.scanMessage({ target, content })

      if (isPublicDeployment) {
        const publicScan = toPublicScanRecord(scan)
        const nextScans = [
          publicScan,
          ...readPublicScans().filter((storedScan) => storedScan.id !== publicScan.id),
        ].slice(0, 50)
        writePublicScans(nextScans)
        applyPublicScans(nextScans, { systemActive: true })
      } else {
        refreshData().catch(console.error)
      }

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
    [applyPublicScans, refreshData],
  )

  const clearHistory = useCallback(async () => {
    if (isPublicDeployment) {
      writePublicScans([])
      applyPublicScans([], { systemActive: true })
      return
    }

    await apiService.clearHistory()
    await apiService.clearThreatAuditLogs()
    await refreshData()
  }, [applyPublicScans, refreshData])

  const acknowledgeAlert = useCallback(
    async (id) => {
      if (isPublicDeployment) {
        setAlerts((current) => current.filter((alert) => alert.id !== id))
        return
      }

      await apiService.dismissAlert(id)
      await refreshData()
    },
    [refreshData],
  )

  const clearAlerts = useCallback(async () => {
    if (isPublicDeployment) {
      setAlerts([])
      setActiveNotification(null)
      latestDangerousAlertId.current = null
      return
    }

    await apiService.clearAlerts()
    setActiveNotification(null)
    latestDangerousAlertId.current = null
    await refreshData()
  }, [refreshData])

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

  const clearFlaggedThreats = useCallback(async () => {
    await apiService.clearFlaggedThreats()
    await refreshData()
  }, [refreshData])

  const saveNotificationSettings = useCallback(async (settings) => {
    const savedSettings = await apiService.saveNotificationSettings(settings)
    setNotificationSettings(savedSettings)
    return savedSettings
  }, [])

  const sendHistoryDigest = useCallback(() => apiService.sendHistoryDigest(), [])

  const dismissNotification = () => setActiveNotification(null)
  const autoBlock = () => null

  const value = useMemo(
    () => ({
      activeNotification,
      alerts,
      acknowledgeAlert,
      autoBlock,
      clearAlerts,
      clearFlaggedThreats,
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
      saveNotificationSettings,
      sendHistoryDigest,
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
      clearAlerts,
      clearFlaggedThreats,
      clearHistory,
      clearReviewedThreats,
      createScan,
      darkMode,
      flaggedThreats,
      liveFeed,
      liveScanCount,
      notificationSettings,
      scanHistory,
      saveNotificationSettings,
      sendHistoryDigest,
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
