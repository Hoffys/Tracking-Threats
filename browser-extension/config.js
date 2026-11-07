const TRACKING_THREATS_CONFIG = {
  API_BASE_URL: 'https://tracking-threats-production.up.railway.app',
  APP_URL: 'https://tracking-threats-production.up.railway.app/',
}

const TRACKING_THREATS_EMAIL_HOSTS = Object.freeze([
  'mail.google.com',
  'outlook.cloud.microsoft',
  'outlook.live.com',
  'outlook.office.com',
  'outlook.office365.com',
  'mail.yahoo.com',
  'mail.proton.me',
  'app.proton.me',
  'www.icloud.com',
  'mail.zoho.com',
  'mail.aol.com',
  'mail.com',
])

function isSupportedEmailHost(hostname) {
  const host = String(hostname ?? '').toLowerCase().replace(/\.$/, '')
  return TRACKING_THREATS_EMAIL_HOSTS.includes(host) || host.endsWith('.mail.com')
}

function isSupportedEmailSender(sender) {
  if (!sender?.tab || !Number.isInteger(sender.tab.id) || sender.frameId !== 0) return false
  try {
    const messageUrl = new URL(sender.url)
    const tabUrl = new URL(sender.tab.url)
    return messageUrl.protocol === 'https:' && tabUrl.protocol === 'https:' &&
      messageUrl.hostname === tabUrl.hostname && isSupportedEmailHost(tabUrl.hostname)
  } catch {
    return false
  }
}
