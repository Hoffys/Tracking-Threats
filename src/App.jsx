import { AnimatePresence, motion } from 'framer-motion'
import { ThreatProvider } from './context/ThreatProvider'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { LiveMonitor } from './pages/LiveMonitor'
import { EmailAnalyzer } from './pages/EmailAnalyzer'
import { ManualScan } from './pages/ManualScan'
import { ScanHistory } from './pages/ScanHistory'
import { Alerts } from './pages/Alerts'
import { Settings } from './pages/Settings'
import { useState } from 'react'

const pages = {
  dashboard: Dashboard,
  monitor: LiveMonitor,
  email: EmailAnalyzer,
  manual: ManualScan,
  history: ScanHistory,
  alerts: Alerts,
  settings: Settings,
}

function AppShell() {
  const [activePage, setActivePage] = useState('dashboard')
  const ActivePage = pages[activePage]

  return (
    <Layout activePage={activePage} onNavigate={setActivePage}>
      <AnimatePresence mode="wait">
        <motion.div
          key={activePage}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.22, ease: 'easeOut' }}
        >
          <ActivePage onNavigate={setActivePage} />
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
