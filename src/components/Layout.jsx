import {
  Activity,
  Bell,
  CircleX,
  History,
  LayoutDashboard,
  MailSearch,
  Moon,
  Radar,
  ScanLine,
  ShieldCheck,
  ShieldX,
  Sun,
} from 'lucide-react'
import { AnimatePresence, motion } from 'framer-motion'
import { useThreats } from '../hooks/useThreats'

const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'monitor', label: 'Monitor', icon: Radar },
  { id: 'email', label: 'Email', icon: MailSearch },
  { id: 'manual', label: 'Scan', icon: ScanLine },
  { id: 'history', label: 'History', icon: History },
  { id: 'alerts', label: 'Alerts', icon: Bell },
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

  return (
    <div className="min-h-screen bg-slate-100 text-slate-900 transition-colors dark:bg-slate-950 dark:text-slate-100">
      <header className="sticky top-0 z-20 border-b border-slate-200 bg-white/90 backdrop-blur dark:border-slate-800 dark:bg-slate-950/90">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-3 px-4 py-3">
          <button
            className="flex min-w-0 items-center gap-3 text-left"
            type="button"
            onClick={() => onNavigate('dashboard')}
          >
            <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-teal-600 text-white">
              <ShieldCheck size={22} />
            </span>
            <span className="min-w-0">
              <span className="block truncate text-base font-semibold">ThreatTrack</span>
              <span className="block truncate text-xs text-slate-500 dark:text-slate-400">
                Phishing detection console
              </span>
            </span>
          </button>

          <div className="flex items-center gap-2">
            <div className="hidden items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm font-medium text-emerald-700 dark:text-emerald-300 md:flex">
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              {systemActive ? 'System Active' : 'System Idle'}
            </div>
            <div className="hidden items-center gap-2 rounded-full border border-slate-200 px-3 py-2 text-sm text-slate-600 dark:border-slate-800 dark:text-slate-300 lg:flex">
              <Activity size={16} className="text-teal-500" />
              {liveScanCount} live scans
            </div>
            <div className="hidden items-center gap-2 rounded-full border border-slate-200 px-3 py-2 text-sm text-slate-600 dark:border-slate-800 dark:text-slate-300 sm:flex">
              <Activity size={16} className="text-teal-500" />
              {stats.unreadAlerts} active alerts
            </div>
            <button
              type="button"
              aria-label="Toggle dark mode"
              title="Toggle dark mode"
              className="grid h-10 w-10 place-items-center rounded-lg border border-slate-200 bg-white text-slate-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-200"
              onClick={() => setDarkMode((current) => !current)}
            >
              {darkMode ? <Sun size={18} /> : <Moon size={18} />}
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-6xl px-4 pb-28 pt-5 md:pb-8">
        {children}
      </main>

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

      <nav className="fixed inset-x-0 bottom-0 z-30 border-t border-slate-200 bg-white/95 backdrop-blur dark:border-slate-800 dark:bg-slate-950/95">
        <div className="mx-auto grid max-w-6xl grid-cols-6 px-2 py-2">
          {navItems.map((item) => {
            const Icon = item.icon
            const active = activePage === item.id
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onNavigate(item.id)}
                className={`flex min-w-0 flex-col items-center gap-1 rounded-lg px-1 py-2 text-xs font-medium transition ${
                  active
                    ? 'bg-teal-600 text-white'
                    : 'text-slate-500 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-900 dark:hover:text-white'
                }`}
              >
                <Icon size={19} />
                <span className="w-full truncate">{item.label}</span>
              </button>
            )
          })}
        </div>
      </nav>
    </div>
  )
}
