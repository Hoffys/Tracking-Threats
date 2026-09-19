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
import { About } from './pages/About'
import { isPublicDeployment } from './config/deployment'
import { useState } from 'react'

const pages = {
  dashboard: Dashboard,
  monitor: LiveMonitor,
  manual: ManualScan,
  history: ScanHistory,
  alerts: Alerts,
  learn: Learn,
  about: About,
  settings: Settings,
}

const publicPages = new Set([
  'dashboard',
  'learn',
  'about',
  'monitor',
  'manual',
  'history',
  'settings',
])

const getInitialRoute = () => {
  const params = new URLSearchParams(window.location.search)
  const requestedPage = params.get('page')
  const legacyAboutSection = ['methodology', 'privacy'].includes(requestedPage)
    ? requestedPage
    : null
  const requestedSection = params.get('section')
  const aboutSection = legacyAboutSection ?? (requestedSection === 'privacy' ? 'privacy' : 'methodology')
  const page = legacyAboutSection ? 'about' : requestedPage === 'email' ? 'manual' : requestedPage
  const safePage = isPublicDeployment
    ? publicPages.has(page) ? page : 'dashboard'
    : pages[page] ? page : 'dashboard'

  return { page: safePage, aboutSection }
}

function AppShell() {
  const [route, setRoute] = useState(getInitialRoute)
  const { page: activePage, aboutSection } = route
  const ActivePage = pages[activePage]

  const handleNavigate = (page) => {
    const requestedAboutSection = ['methodology', 'privacy'].includes(page) ? page : null
    const nextPage = requestedAboutSection ? 'about' : page === 'email' ? 'manual' : page
    const safePage = isPublicDeployment && !publicPages.has(nextPage) ? 'manual' : nextPage
    const nextAboutSection = requestedAboutSection ?? (safePage === 'about' ? aboutSection : 'methodology')
    setRoute({ page: safePage, aboutSection: nextAboutSection })
    const url = new URL(window.location.href)
    url.searchParams.set('page', safePage)
    if (safePage === 'about') url.searchParams.set('section', nextAboutSection)
    else url.searchParams.delete('section')
    url.searchParams.delete('blocked')
    window.history.replaceState({}, '', url)
  }

  return (
    <Layout activePage={activePage} onNavigate={handleNavigate}>
      <AnimatePresence mode="wait">
        <motion.div
          key={activePage === 'about' ? `${activePage}:${aboutSection}` : activePage}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.22, ease: 'easeOut' }}
        >
          <ActivePage aboutSection={aboutSection} onNavigate={handleNavigate} />
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
