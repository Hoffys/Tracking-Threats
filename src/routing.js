const routePages = new Set([
  'dashboard', 'monitor', 'manual', 'history', 'alerts', 'learn', 'about', 'settings', 'admin',
])

const publicPages = new Set([
  'dashboard', 'learn', 'about', 'monitor', 'manual', 'history', 'settings', 'admin',
])

export function resolveRoute(href, publicDeployment = false) {
  const url = new URL(href, 'http://localhost')
  if (url.pathname.replace(/\/$/, '') === '/privacy') {
    return { page: 'privacyPolicy', aboutSection: 'methodology' }
  }
  if (url.pathname.replace(/\/$/, '') === '/admin') {
    return { page: 'admin', aboutSection: 'methodology' }
  }
  if (url.pathname !== '/' && url.pathname !== '') {
    return { page: null, aboutSection: 'methodology', notFound: true }
  }

  const requestedPage = url.searchParams.get('page')
  const legacyAboutSection = ['methodology', 'privacy'].includes(requestedPage) ? requestedPage : null
  const aboutSection = legacyAboutSection ?? (url.searchParams.get('section') === 'privacy' ? 'privacy' : 'methodology')
  const page = requestedPage === null
    ? 'dashboard'
    : legacyAboutSection
      ? 'about'
      : requestedPage === 'email'
        ? 'manual'
        : requestedPage
  if (!routePages.has(page)) return { page: null, aboutSection, notFound: true }

  if (publicDeployment && !publicPages.has(page)) {
    return { page: 'dashboard', aboutSection: 'methodology', canonicalize: true }
  }

  return { page, aboutSection }
}

export function getPageUrl(page, aboutSection = 'methodology') {
  if (page === 'privacyPolicy') return '/privacy'
  if (page === 'admin') return '/admin'
  const url = new URL('/', 'http://localhost')
  url.searchParams.set('page', page)
  if (page === 'about') url.searchParams.set('section', aboutSection)
  return `${url.pathname}${url.search}`
}
