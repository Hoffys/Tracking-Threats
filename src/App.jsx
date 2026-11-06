import { AnimatePresence, motion } from 'framer-motion'
import { ThreatProvider } from './context/ThreatProvider'
import { Layout } from './components/Layout'
import { isPublicDeployment } from './config/deployment'
import { lazy, Suspense, useEffect, useState } from 'react'
import { getPageUrl, resolveRoute } from './routing'

const Dashboard = lazy(() => import('./pages/Dashboard').then((module) => ({ default: module.Dashboard })))
const LiveMonitor = lazy(() => import('./pages/LiveMonitor').then((module) => ({ default: module.LiveMonitor })))
const ManualScan = lazy(() => import('./pages/ManualScan').then((module) => ({ default: module.ManualScan })))
const ScanHistory = lazy(() => import('./pages/ScanHistory').then((module) => ({ default: module.ScanHistory })))
const Alerts = lazy(() => import('./pages/Alerts').then((module) => ({ default: module.Alerts })))
const Learn = lazy(() => import('./pages/Learn').then((module) => ({ default: module.Learn })))
const Settings = lazy(() => import('./pages/Settings').then((module) => ({ default: module.Settings })))
const About = lazy(() => import('./pages/About').then((module) => ({ default: module.About })))
const PublicPrivacyPolicy = lazy(() => import('./pages/PublicPrivacyPolicy').then((module) => ({ default: module.PublicPrivacyPolicy })))
const Admin = lazy(() => import('./pages/Admin').then((module) => ({ default: module.Admin })))

const pages = {
  dashboard: Dashboard,
  monitor: LiveMonitor,
  manual: ManualScan,
  history: ScanHistory,
  alerts: Alerts,
  learn: Learn,
  about: About,
  privacyPolicy: PublicPrivacyPolicy,
  settings: Settings,
  admin: Admin,
}

const getInitialRoute = () => resolveRoute(window.location.href, isPublicDeployment)

function AppShell() {
  const [route, setRoute] = useState(getInitialRoute)
  useEffect(() => {
    const handlePopState = () => {
      const nextRoute = getInitialRoute()
      if (nextRoute.canonicalize) window.history.replaceState({}, '', getPageUrl('dashboard'))
      setRoute(nextRoute)
    }
    window.addEventListener('popstate', handlePopState)
    return () => window.removeEventListener('popstate', handlePopState)
  }, [])
  useEffect(() => {
    if (route.canonicalize) window.history.replaceState({}, '', getPageUrl('dashboard'))
  }, [route])
  const { page: activePage, aboutSection } = route
  const ActivePage = pages[activePage]

  const handleNavigate = (page) => {
    if (page === 'privacy-policy') page = 'privacyPolicy'
    const requestedAboutSection = ['methodology', 'privacy'].includes(page) ? page : null
    const nextPage = requestedAboutSection ? 'about' : page === 'email' ? 'manual' : page
    if (!pages[nextPage]) return
    const safePage = isPublicDeployment && !['dashboard', 'learn', 'about', 'monitor', 'manual', 'history', 'settings', 'admin', 'privacyPolicy'].includes(nextPage)
      ? 'manual'
      : nextPage
    const nextAboutSection = requestedAboutSection ?? (safePage === 'about' ? aboutSection : 'methodology')
    const nextRoute = { page: safePage, aboutSection: nextAboutSection }
    const nextUrl = getPageUrl(safePage, nextAboutSection)
    if (`${window.location.pathname}${window.location.search}` !== nextUrl) {
      window.history.pushState({}, '', nextUrl)
    }
    setRoute(nextRoute)
  }

  return (
    <ThreatProvider pauseAutoRefresh={activePage === 'admin'}>
      <Layout activePage={activePage} onNavigate={handleNavigate}>
        <AnimatePresence mode="wait">
          <motion.div
            key={route.notFound ? 'notFound' : activePage === 'about' ? `${activePage}:${aboutSection}` : activePage}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.22, ease: 'easeOut' }}
          >
            <Suspense fallback={<div className="rounded-lg border border-slate-200 p-5 text-sm text-slate-500 dark:border-slate-800">Loading page...</div>}>
              {route.notFound ? (
                <div className="space-y-3 rounded-lg border border-slate-200 p-6 dark:border-slate-800">
                  <h1 className="text-xl font-semibold">Page not found</h1>
                  <p className="text-sm text-slate-600 dark:text-slate-300">This address does not match an available page.</p>
                  <button type="button" onClick={() => handleNavigate('dashboard')} className="rounded-lg bg-teal-600 px-4 py-2 text-sm font-semibold text-white">Go to Dashboard</button>
                </div>
              ) : (
                <ActivePage aboutSection={aboutSection} onNavigate={handleNavigate} />
              )}
            </Suspense>
          </motion.div>
        </AnimatePresence>
      </Layout>
    </ThreatProvider>
  )
}

export default function App() {
  return <AppShell />
}
