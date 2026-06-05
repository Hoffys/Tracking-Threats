import { AnimatePresence, motion } from 'framer-motion'
import { ThreatProvider } from './context/ThreatProvider'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { LiveMonitor } from './pages/LiveMonitor'
import { ManualScan } from './pages/ManualScan'
import { ScanHistory } from './pages/ScanHistory'
import { Alerts } from './pages/Alerts'
import { Learn } from './pages/Learn'
import { Settings } from './pages/Settings'
import { useState } from 'react'

const pages = {
  dashboard: Dashboard,
  monitor: LiveMonitor,
  manual: ManualScan,
  history: ScanHistory,
  alerts: Alerts,
  learn: Learn,
  settings: Settings,
}

const getInitialPage = () => {
  const page = new URLSearchParams(window.location.search).get('page')
  if (page === 'email') return 'manual'
  return pages[page] ? page : 'dashboard'
}

function AppShell() {
  const [activePage, setActivePage] = useState(getInitialPage)
  const ActivePage = pages[activePage]

  const handleNavigate = (page) => {
    const nextPage = page === 'email' ? 'manual' : page
    setActivePage(nextPage)
    const url = new URL(window.location.href)
    url.searchParams.set('page', nextPage)
    url.searchParams.delete('blocked')
    window.history.replaceState({}, '', url)
  }

  return (
    <Layout activePage={activePage} onNavigate={handleNavigate}>
      <AnimatePresence mode="wait">
        <motion.div
          key={activePage}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.22, ease: 'easeOut' }}
        >
          <ActivePage onNavigate={handleNavigate} />
        </motion.div>
      </AnimatePresence>
    </Layout>
  )
}

export default function App() {
  return (
    <ThreatProvider>
      <AppShell />
    </ThreatProvider>
  )
}
