import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ThreatContext } from './ThreatContext'
import { isPublicDeployment } from '../config/deployment'
import { apiService, clearClientCredential, ensureClientCredential, readClientCredential } from '../services/api'

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
  mailStatus: {
    configured: false,
    enabled: true,
    missing: [],
  },
}

const publicScansStorageKeyPrefix = 'threattrack:public-scans'
const publicHiddenScansStorageKeyPrefix = 'threattrack:public-hidden-scan-ids'
const publicHistoryClearedBeforeStorageKeyPrefix = 'threattrack:public-history-cleared-before'

const getPublicSessionKey = (clientId) => clientId || 'local'
const getPublicScansStorageKey = (clientId) =>
  `${publicScansStorageKeyPrefix}:${getPublicSessionKey(clientId)}`
const getPublicHiddenScansStorageKey = (clientId) =>
  `${publicHiddenScansStorageKeyPrefix}:${getPublicSessionKey(clientId)}`
const getPublicHistoryClearedBeforeStorageKey = (clientId) =>
  `${publicHistoryClearedBeforeStorageKeyPrefix}:${getPublicSessionKey(clientId)}`

const readPublicClientId = () => readClientCredential()?.clientId ?? ''

const readPublicScans = (clientId = '') => {
  try {
    const stored = localStorage.getItem(getPublicScansStorageKey(clientId))
    return stored ? JSON.parse(stored) : []
  } catch {
    return []
  }
}

const writePublicScans = (scans, clientId = '') => {
  localStorage.setItem(getPublicScansStorageKey(clientId), JSON.stringify(scans.slice(0, 50)))
}

const readPublicHiddenScanIds = (clientId = '') => {
  try {
    const stored = localStorage.getItem(getPublicHiddenScansStorageKey(clientId))
    return new Set(stored ? JSON.parse(stored) : [])
  } catch {
    return new Set()
  }
}

const readPublicHistoryClearedBefore = (clientId = '') => {
  try {
    return Number(localStorage.getItem(getPublicHistoryClearedBeforeStorageKey(clientId)) ?? 0)
  } catch {
    return 0
  }
}

const clearPublicClientStorage = (clientId = '') => {
  localStorage.removeItem(getPublicScansStorageKey(clientId))
  localStorage.removeItem(getPublicHiddenScansStorageKey(clientId))
  localStorage.removeItem(getPublicHistoryClearedBeforeStorageKey(clientId))
}

const filterVisiblePublicScans = (scans, clientId = '') => {
  const hiddenScanIds = readPublicHiddenScanIds(clientId)
  const clearedBefore = readPublicHistoryClearedBefore(clientId)
  return scans.filter((scan) => {
    if (hiddenScanIds.has(scan.id)) return false
    if (!clearedBefore) return true
    return new Date(scan.date).getTime() > clearedBefore
  })
}

const mergePublicScans = (...scanGroups) => {
  const byId = new Map()
  scanGroups.flat().forEach((scan) => {
    if (!scan?.id) return
    byId.set(scan.id, scan)
  })
  return Array.from(byId.values())
    .sort((left, right) => new Date(right.date).getTime() - new Date(left.date).getTime())
    .slice(0, 50)
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
  const [publicClientId, setPublicClientId] = useState(() => (isPublicDeployment ? readPublicClientId() : ''))
  const initialPublicScans = isPublicDeployment
    ? filterVisiblePublicScans(readPublicScans(publicClientId), publicClientId)
    : []
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
      const [health, activity] = await Promise.all([
        apiService.getHealth(),
        publicClientId
          ? apiService.getPublicActivity(publicClientId).catch(() => null)
          : Promise.resolve(null),
      ])
      const nextScans = activity?.scans
        ? filterVisiblePublicScans(
            mergePublicScans(activity.scans, readPublicScans(publicClientId)),
            publicClientId,
          )
        : filterVisiblePublicScans(readPublicScans(publicClientId), publicClientId)
      writePublicScans(nextScans, publicClientId)
      applyPublicScans(nextScans, health)
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
  }, [applyPublicScans, publicClientId])

  useEffect(() => {
    localStorage.setItem('threattrack:dark-mode', JSON.stringify(darkMode))
    document.documentElement.classList.toggle('dark', darkMode)
  }, [darkMode])

  useEffect(() => {
    if (!isPublicDeployment) return
    ensureClientCredential()
      .then(({ clientId }) => setPublicClientId(clientId))
      .catch(console.error)
  }, [])

  useEffect(() => {
    if (isPublicDeployment && !publicClientId) return
    apiService
      .getNotificationSettings(isPublicDeployment ? publicClientId : '')
      .then((settings) => setNotificationSettings((current) => ({ ...current, ...settings })))
      .catch(console.error)
  }, [publicClientId])

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
      privacyAccepted = false,
      privacyNoticeVersion = '2026.09',
    }) => {
      const privacyMetadata = { privacyAccepted, privacyNoticeVersion }
      const clientId = isPublicDeployment
        ? (await ensureClientCredential()).clientId
        : ''
      if (isPublicDeployment && clientId !== publicClientId) setPublicClientId(clientId)
      const scan =
        type === 'URL' || type === 'Domain'
          ? await apiService.scanUrl(target, {
              source: isPublicDeployment ? 'public-web-scan' : 'api',
              clientId,
              ...privacyMetadata,
            })
          : type === 'Email'
            ? await apiService.scanEmail({
                sender: sender ?? target,
                subject: subject ?? content.split('\n')[0] ?? '',
                body: body ?? (content.split('\n').slice(1).join('\n') || content),
                source: isPublicDeployment ? 'public-web-scan' : 'api',
                clientId,
                ...privacyMetadata,
              })
            : type === 'File'
              ? await apiService.scanFile({
                  fileName: fileName ?? target,
                  mimeType,
                  size,
                  content,
                  sha256,
                  source: isPublicDeployment ? 'public-web-scan' : 'api',
                  clientId,
                  ...privacyMetadata,
                })
              : await apiService.scanMessage({
                  target,
                  content,
                  source: isPublicDeployment ? 'public-web-scan' : 'api',
                  clientId,
                  ...privacyMetadata,
                })

      if (isPublicDeployment) {
        const publicScan = toPublicScanRecord(scan)
        const nextScans = [
          publicScan,
          ...readPublicScans(clientId).filter(
            (storedScan) => storedScan.id !== publicScan.id,
          ),
        ].slice(0, 50)
        writePublicScans(nextScans, clientId)
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
    [applyPublicScans, publicClientId, refreshData],
  )

  const clearHistory = useCallback(async () => {
    if (isPublicDeployment) {
      const clientId = (await ensureClientCredential()).clientId
      await apiService.deletePublicHistory(clientId)
      clearPublicClientStorage(clientId)
      applyPublicScans([], { systemActive: true })
      return
    }

    await apiService.clearHistory()
    await apiService.clearThreatAuditLogs()
    await refreshData()
  }, [applyPublicScans, refreshData])

  const deleteMyData = useCallback(async () => {
    if (isPublicDeployment) {
      const clientId = (await ensureClientCredential()).clientId
      const result = await apiService.deletePublicClientData(clientId)
      clearPublicClientStorage(clientId)
      clearClientCredential()
      setPublicClientId('')
      localStorage.removeItem('threattrack:notification-settings')
      setNotificationSettings(defaultNotificationSettings)
      applyPublicScans([], { systemActive: true })
      ensureClientCredential()
        .then(({ clientId: nextClientId }) => setPublicClientId(nextClientId))
        .catch(console.error)
      return result
    }

    await apiService.clearHistory()
    await apiService.clearAlerts()
    await apiService.clearThreatAuditLogs()
    await refreshData()
    return { ok: true }
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

  const saveNotificationSettings = useCallback(
    async (settings) => {
      const clientId = isPublicDeployment
        ? (await ensureClientCredential()).clientId
        : ''
      const savedSettings = await apiService.saveNotificationSettings(
        settings,
        clientId,
      )
      setNotificationSettings(savedSettings)
      return savedSettings
    },
    [],
  )

  const sendHistoryDigest = useCallback(
    async (settings = notificationSettings) => {
      const clientId = isPublicDeployment
        ? (await ensureClientCredential()).clientId
        : ''
      return apiService.sendHistoryDigest(settings, clientId)
    },
    [notificationSettings],
  )

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
      deleteMyData,
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
      deleteMyData,
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
