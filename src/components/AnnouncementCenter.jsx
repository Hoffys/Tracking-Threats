import { Download, Megaphone, RefreshCw, X } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { apiService, extensionDownloadUrl } from '../services/api'

const readAnnouncementKey = 'threattrack:read-announcements'

const readStoredIds = () => {
  try {
    const value = JSON.parse(localStorage.getItem(readAnnouncementKey) ?? '[]')
    return Array.isArray(value) ? value.map(String).slice(-100) : []
  } catch {
    return []
  }
}

const saveStoredIds = (ids) => {
  try {
    localStorage.setItem(readAnnouncementKey, JSON.stringify(ids.slice(-100)))
  } catch {
    // The announcement panel still works when storage is unavailable.
  }
}

const formatPublishedDate = (value) => {
  if (!value) return ''
  const date = new Date(value)
  return Number.isNaN(date.getTime())
    ? ''
    : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(date)
}

const priorityStyles = {
  critical: 'border-rose-300 bg-rose-50 dark:border-rose-900 dark:bg-rose-950/30',
  important: 'border-amber-300 bg-amber-50 dark:border-amber-900 dark:bg-amber-950/25',
  normal: 'border-slate-200 bg-slate-50 dark:border-slate-700 dark:bg-slate-800/60',
}

export function AnnouncementCenter() {
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [announcements, setAnnouncements] = useState([])
  const [latestVersion, setLatestVersion] = useState(null)
  const [readIds, setReadIds] = useState(readStoredIds)
  const openRef = useRef(false)

  const markAnnouncementsRead = useCallback((items) => {
    if (items.length === 0) return
    setReadIds((current) => {
      const next = Array.from(new Set([
        ...current,
        ...items.map((announcement) => String(announcement.id)),
      ])).slice(-100)
      saveStoredIds(next)
      return next
    })
  }, [])

  const loadAnnouncements = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const payload = await apiService.getPublicAnnouncements()
      const nextAnnouncements = Array.isArray(payload?.announcements) ? payload.announcements : []
      setAnnouncements(nextAnnouncements)
      setLatestVersion(payload?.latestVersion || null)
      if (openRef.current) markAnnouncementsRead(nextAnnouncements)
    } catch {
      setError('Announcements are temporarily unavailable.')
    } finally {
      setLoading(false)
    }
  }, [markAnnouncementsRead])

  useEffect(() => {
    let active = true
    apiService.getPublicAnnouncements()
      .then((payload) => {
        if (!active) return
        const nextAnnouncements = Array.isArray(payload?.announcements) ? payload.announcements : []
        setAnnouncements(nextAnnouncements)
        setLatestVersion(payload?.latestVersion || null)
        if (openRef.current) markAnnouncementsRead(nextAnnouncements)
      })
      .catch(() => {
        if (active) setError('Announcements are temporarily unavailable.')
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => { active = false }
  }, [markAnnouncementsRead])

  useEffect(() => {
    if (!open) return undefined
    const closeOnEscape = (event) => {
      if (event.key === 'Escape') {
        openRef.current = false
        setOpen(false)
      }
    }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [open])

  const unreadCount = useMemo(() => {
    const read = new Set(readIds)
    return announcements.filter((announcement) => !read.has(String(announcement.id))).length
  }, [announcements, readIds])

  const buttonLabel = unreadCount > 0
    ? `Announcements, ${unreadCount} unread`
    : 'Announcements'

  const toggleAnnouncements = () => {
    const nextOpen = !open
    openRef.current = nextOpen
    setOpen(nextOpen)
    if (nextOpen) markAnnouncementsRead(announcements)
  }

  const closeAnnouncements = () => {
    openRef.current = false
    setOpen(false)
  }

  return (
    <div className="relative">
      <button
        type="button"
        aria-label={buttonLabel}
        title={buttonLabel}
        aria-expanded={open}
        aria-controls="public-announcements"
        onClick={toggleAnnouncements}
        className="relative grid h-10 w-10 place-items-center rounded-lg border border-emerald-300 bg-white text-emerald-800 transition hover:bg-emerald-50 dark:border-emerald-800 dark:bg-slate-900 dark:text-emerald-200 dark:hover:bg-slate-800"
      >
        <Megaphone size={19} />
        {unreadCount > 0 && (
          <span className="absolute -right-1.5 -top-1.5 grid min-h-5 min-w-5 place-items-center rounded-full bg-rose-600 px-1 text-[10px] font-bold leading-none text-white ring-2 ring-white dark:ring-slate-900">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <section
          id="public-announcements"
          aria-label="System and extension announcements"
          className="fixed inset-x-4 top-20 z-50 mx-auto max-h-[calc(100vh-6rem)] max-w-lg overflow-y-auto rounded-xl border border-emerald-200 bg-white p-4 text-left shadow-2xl dark:border-slate-700 dark:bg-slate-900 sm:absolute sm:inset-x-auto sm:right-0 sm:top-12 sm:mx-0 sm:w-[28rem]"
        >
          <div className="flex items-start justify-between gap-3 border-b border-slate-200 pb-3 dark:border-slate-700">
            <div>
              <h2 className="flex items-center gap-2 font-semibold">
                <Megaphone size={18} className="text-emerald-600 dark:text-emerald-300" />
                Announcements
              </h2>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                Extension updates, new features, and system notices from our staff.
              </p>
            </div>
            <button
              type="button"
              aria-label="Close announcements"
              onClick={closeAnnouncements}
              className="grid h-8 w-8 shrink-0 place-items-center rounded-md text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800"
            >
              <X size={18} />
            </button>
          </div>

          {latestVersion && (
            <div className="mt-3 rounded-lg bg-emerald-50 px-3 py-2 text-sm text-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-200">
              Latest extension version: <strong>v{latestVersion}</strong>
            </div>
          )}

          {loading && <p className="py-6 text-center text-sm text-slate-500">Checking for announcements...</p>}

          {!loading && error && (
            <div className="py-5 text-center">
              <p className="text-sm text-rose-700 dark:text-rose-300">{error}</p>
              <button
                type="button"
                onClick={loadAnnouncements}
                className="mt-3 inline-flex items-center gap-2 rounded-lg border border-slate-300 px-3 py-2 text-sm font-semibold dark:border-slate-600"
              >
                <RefreshCw size={15} /> Try again
              </button>
            </div>
          )}

          {!loading && !error && announcements.length === 0 && (
            <p className="py-6 text-center text-sm text-slate-500 dark:text-slate-400">
              No new announcements right now.
            </p>
          )}

          {!loading && !error && announcements.length > 0 && (
            <div className="mt-3 space-y-3">
              {announcements.map((announcement) => (
                <article
                  key={announcement.id}
                  className={`rounded-lg border p-3 ${priorityStyles[announcement.priority] ?? priorityStyles.normal}`}
                >
                  <div className="flex flex-wrap items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                    <span>{announcement.type}</span>
                    {announcement.priority !== 'normal' && <span>• {announcement.priority}</span>}
                    {announcement.publishedAt && <span>• {formatPublishedDate(announcement.publishedAt)}</span>}
                  </div>
                  <h3 className="mt-1 font-semibold text-slate-950 dark:text-white">{announcement.title}</h3>
                  <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-700 dark:text-slate-300">
                    {announcement.message}
                  </p>
                  {announcement.type === 'update' && announcement.targetVersion && (
                    <a
                      href={extensionDownloadUrl}
                      className="mt-3 inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-3 py-2 text-sm font-semibold text-white transition hover:bg-emerald-700"
                    >
                      <Download size={16} /> Download Extension v{announcement.targetVersion}
                    </a>
                  )}
                </article>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  )
}
