import {
  Activity,
  Bell,
  BookOpenCheck,
  CircleX,
  History,
  LayoutDashboard,
  Moon,
  Radar,
  ScanLine,
  Settings,
  ShieldX,
  Sun,
} from 'lucide-react'
import { AnimatePresence, motion } from 'framer-motion'
import { useThreats } from '../hooks/useThreats'

const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'learn', label: 'Learn', icon: BookOpenCheck },
  { id: 'monitor', label: 'Monitor', icon: Radar },
  { id: 'manual', label: 'Scan', icon: ScanLine },
  { id: 'history', label: 'History', icon: History },
  { id: 'alerts', label: 'Alerts', icon: Bell },
  { id: 'settings', label: 'Settings', icon: Settings },
]

export function Layout({ activePage, children, onNavigate }) {
  const {
    activeNotification,
    darkMode,
    dismissNotification,
    liveScanCount,
    setDarkMode,
    stats,
    systemActive,
  } = useThreats()

  const renderNavItem = (item, variant = 'sidebar') => {
    const Icon = item.icon
    const active = activePage === item.id
    const isSidebar = variant === 'sidebar'

    return (
      <button
        key={item.id}
        type="button"
        title={item.label}
        onClick={() => onNavigate(item.id)}
        className={`group flex min-w-0 items-center transition ${
          isSidebar
            ? `gap-3 rounded-lg px-3 py-3 text-sm font-semibold ${
                active
                  ? 'bg-emerald-500 text-white shadow-sm shadow-emerald-500/25'
                  : 'text-emerald-800 hover:bg-emerald-50 hover:text-emerald-950 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-emerald-300'
              }`
            : `flex-col gap-1 rounded-lg px-1 py-2 text-xs font-medium ${
                active
                  ? 'bg-emerald-500 text-white'
                  : 'text-emerald-800 hover:bg-emerald-50 hover:text-emerald-950 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-emerald-300'
              }`
        }`}
      >
        <span
          className={`grid shrink-0 place-items-center ${
            isSidebar
              ? `h-9 w-9 rounded-lg ${
                  active
                    ? 'bg-white/20 text-white'
                    : 'bg-emerald-50 text-emerald-700 group-hover:text-emerald-900 dark:bg-slate-800 dark:text-slate-300 dark:group-hover:text-emerald-300'
                }`
              : ''
          }`}
        >
          <Icon size={isSidebar ? 18 : 19} />
        </span>
        <span className={isSidebar ? 'truncate' : 'w-full truncate'}>{item.label}</span>
      </button>
    )
  }

  return (
    <div className="min-h-screen bg-emerald-50 text-slate-950 transition-colors dark:bg-slate-950 dark:text-slate-100">
      <aside className="fixed inset-y-0 left-0 z-30 flex w-56 flex-col border-r border-emerald-100 bg-white/95 px-4 py-4 backdrop-blur dark:border-slate-800 dark:bg-slate-900/95 md:w-72">
        <button
          className="flex min-w-0 items-center gap-3 rounded-lg p-2 text-left transition hover:bg-emerald-50 dark:hover:bg-slate-800"
          type="button"
          onClick={() => onNavigate('dashboard')}
        >
          <span className="grid h-11 w-11 shrink-0 place-items-center overflow-hidden rounded-lg bg-emerald-500 ring-1 ring-emerald-300/50">
            <img
              src="/tracking-threats-logo.png"
              alt=""
              aria-hidden="true"
              className="h-full w-full object-cover"
            />
          </span>
          <span className="min-w-0">
            <span className="block truncate text-base font-semibold">Tracking Threats</span>
            <span className="block truncate text-xs text-emerald-700 dark:text-emerald-300">
              Local phishing defense
            </span>
          </span>
        </button>

        <nav className="mt-6 flex flex-1 flex-col gap-1" aria-label="Primary navigation">
          {navItems.map((item) => renderNavItem(item))}
        </nav>

        <div className="space-y-3 border-t border-emerald-100 pt-4 dark:border-slate-800">
          <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 dark:border-emerald-900/70 dark:bg-emerald-950/25">
            <div className="flex items-center justify-between gap-3">
              <span className="text-sm font-semibold">System</span>
              <span className="relative flex h-3 w-3 items-center justify-center">
                {systemActive && (
                  <span className="absolute h-3 w-3 animate-ping rounded-full bg-emerald-400 opacity-75" />
                )}
                <span
                  className={`relative h-2.5 w-2.5 rounded-full ${
                    systemActive
                      ? 'bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,0.95)]'
                      : 'bg-slate-400'
                  }`}
                />
              </span>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-emerald-700 dark:text-emerald-300">
              <div>
                <p className="text-lg font-semibold text-slate-950 dark:text-white">
                  {liveScanCount}
                </p>
                <p>Live scans</p>
              </div>
              <div>
                <p className="text-lg font-semibold text-slate-950 dark:text-white">
                  {stats.unreadAlerts}
                </p>
                <p>Alerts</p>
              </div>
            </div>
          </div>

          <button
            type="button"
            className="theme-toggle flex w-full items-center justify-between rounded-lg border border-emerald-100 bg-white px-3 py-3 text-sm font-semibold text-emerald-800 transition dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            onClick={() => setDarkMode((current) => !current)}
          >
            <span>{darkMode ? 'Light mode' : 'Dark mode'}</span>
            {darkMode ? (
              <Sun key="sun" size={18} className="theme-toggle-icon text-amber-300" />
            ) : (
              <Moon key="moon" size={18} className="theme-toggle-icon text-slate-600" />
            )}
          </button>
        </div>
      </aside>

      <div className="pl-56 md:pl-72">
        <header className="sticky top-0 z-20 border-b border-emerald-100 bg-white/90 backdrop-blur dark:border-slate-800 dark:bg-slate-900/90">
          <div className="mx-auto flex max-w-7xl items-center justify-end gap-3 px-4 py-3 lg:px-6">
          <button
            className="hidden min-w-0 items-center gap-3 text-left"
            type="button"
            onClick={() => onNavigate('dashboard')}
          >
            <span className="grid h-10 w-10 shrink-0 place-items-center overflow-hidden rounded-lg bg-slate-950 ring-1 ring-teal-400/30">
              <img
                src="/tracking-threats-logo.png"
                alt=""
                aria-hidden="true"
                className="h-full w-full object-cover"
              />
            </span>
            <span className="min-w-0">
              <span className="block truncate text-base font-semibold">Tracking Threats</span>
              <span className="block truncate text-xs text-slate-500 dark:text-slate-400">
                Real-time monitoring and protection against phishing attacks
              </span>
            </span>
          </button>

          <div className="flex items-center gap-2">
            <div className="hidden items-center gap-2 rounded-full border border-emerald-400 bg-emerald-100 px-3 py-2 text-sm font-medium text-emerald-700 dark:border-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300 md:flex">
              <span className="relative flex h-3 w-3 items-center justify-center">
                {systemActive && (
                  <span className="absolute h-3 w-3 animate-ping rounded-full bg-emerald-400 opacity-75" />
                )}
                <span
                  className={`relative h-2.5 w-2.5 rounded-full ${
                    systemActive
                      ? 'bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,0.95)]'
                      : 'bg-slate-400'
                  }`}
                />
              </span>
              {systemActive ? 'System Active' : 'System Idle'}
            </div>
            <div className="status-glow hidden items-center gap-2 rounded-full border border-emerald-100 bg-white/70 px-3 py-2 text-sm text-emerald-800 dark:border-slate-700 dark:bg-slate-800/70 dark:text-slate-300 lg:flex">
              <Activity size={16} className="activity-glow text-emerald-500" />
              {liveScanCount} live scans
            </div>
            <div className="status-glow hidden items-center gap-2 rounded-full border border-emerald-100 bg-white/70 px-3 py-2 text-sm text-emerald-800 dark:border-slate-700 dark:bg-slate-800/70 dark:text-slate-300 sm:flex">
              <Activity size={16} className="activity-glow text-emerald-500" />
              {stats.unreadAlerts} active alerts
            </div>
            <button
              type="button"
              aria-label="Toggle dark mode"
              title="Toggle dark mode"
              className="hidden h-10 w-10 place-items-center rounded-lg border border-slate-200 bg-white text-slate-700 transition dark:border-slate-800 dark:bg-slate-900 dark:text-slate-200"
              onClick={() => setDarkMode((current) => !current)}
            >
              {darkMode ? (
                <Sun key="sun" size={18} className="theme-toggle-icon text-amber-300" />
              ) : (
                <Moon key="moon" size={18} className="theme-toggle-icon text-slate-600" />
              )}
            </button>
          </div>
          </div>
        </header>

        <main className="mx-auto w-full max-w-7xl px-4 pb-8 pt-5 lg:px-6">
          {children}
        </main>
      </div>

      <AnimatePresence>
        {activeNotification && (
          <motion.div
            initial={{ opacity: 0, y: 18, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 12, scale: 0.98 }}
            transition={{ duration: 0.18 }}
            className="fixed inset-x-4 bottom-24 z-40 mx-auto max-w-md rounded-lg border border-rose-400/50 bg-rose-600 p-4 text-white shadow-2xl md:bottom-6 md:right-6 md:left-auto md:mx-0"
            role="alert"
          >
            <div className="flex items-start gap-3">
              <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-white/15">
                <ShieldX size={21} />
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex items-start justify-between gap-3">
                  <p className="font-semibold">Dangerous Threat Detected</p>
                  <button
                    aria-label="Dismiss alert"
                    className="grid h-7 w-7 shrink-0 place-items-center rounded-md text-white/80 hover:bg-white/10 hover:text-white"
                    type="button"
                    onClick={dismissNotification}
                  >
                    <CircleX size={18} />
                  </button>
                </div>
                <p className="mt-1 text-sm text-rose-50">
                  {activeNotification.threatType} • {activeNotification.riskLevel} •{' '}
                  {activeNotification.source}
                </p>
                <p className="mt-2 text-sm text-white">
                  {activeNotification.recommendedAction}
                </p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <nav className="hidden">
        <div className="mx-auto grid max-w-6xl grid-cols-6 px-2 py-2">
          {navItems.map((item) => renderNavItem(item, 'bottom'))}
        </div>
      </nav>
    </div>
  )
}
