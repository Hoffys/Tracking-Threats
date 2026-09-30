import { AnimatePresence, motion } from 'framer-motion'
import { ThreatProvider } from './context/ThreatProvider'
import { Layout } from './components/Layout'
import { isPublicDeployment } from './config/deployment'
import { lazy, Suspense, useState } from 'react'

const Dashboard = lazy(() => import('./pages/Dashboard').then((module) => ({ default: module.Dashboard })))
const LiveMonitor = lazy(() => import('./pages/LiveMonitor').then((module) => ({ default: module.LiveMonitor })))
const ManualScan = lazy(() => import('./pages/ManualScan').then((module) => ({ default: module.ManualScan })))
const ScanHistory = lazy(() => import('./pages/ScanHistory').then((module) => ({ default: module.ScanHistory })))
const Alerts = lazy(() => import('./pages/Alerts').then((module) => ({ default: module.Alerts })))
const Learn = lazy(() => import('./pages/Learn').then((module) => ({ default: module.Learn })))
const Settings = lazy(() => import('./pages/Settings').then((module) => ({ default: module.Settings })))
const About = lazy(() => import('./pages/About').then((module) => ({ default: module.About })))
const Admin = lazy(() => import('./pages/Admin').then((module) => ({ default: module.Admin })))

const pages = {
  dashboard: Dashboard,
  monitor: LiveMonitor,
  manual: ManualScan,
  history: ScanHistory,
  alerts: Alerts,
  learn: Learn,
  about: About,
  settings: Settings,
  admin: Admin,
}

const publicPages = new Set([
  'dashboard',
  'learn',
  'about',
  'monitor',
  'manual',
  'history',
  'settings',
  'admin',
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
    url.searchParams.delete('scan')
    url.searchParams.delete('preview')
    url.hash = ''
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
          <Suspense fallback={<div className="rounded-lg border border-slate-200 p-5 text-sm text-slate-500 dark:border-slate-800">Loading page...</div>}>
            <ActivePage aboutSection={aboutSection} onNavigate={handleNavigate} />
          </Suspense>
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
