import { createEmailScan, createUrlScan } from '../controllers/scanController.js'

const sampleUrls = [
  'https://cloudflare.com/cdn-cgi/trace',
  'https://www.google.com/generate_204',
  'http://paypal-verify.xyz/login',
  'https://bit.ly/account-fix',
  'http://192.168.18.44/signin',
]

const sampleEmails = [
  {
    sender: 'newsletter@gmail.com',
    subject: 'Weekly update',
    body: 'Your weekly product update is ready to review.',
  },
  {
    sender: 'security@paypaI-alerts.com',
    subject: 'Urgent account suspended',
    body: 'Act now. Verify your password at http://paypal-verify.xyz/login',
  },
  {
    sender: 'claims@lottery-prize.ga',
    subject: 'You are a winner',
    body: 'Claim your lottery prize before it expires.',
  },
]

const pickRandom = (items) => items[Math.floor(Math.random() * items.length)]

export function startAutoMonitor() {
  const run = async () => {
    await createUrlScan(pickRandom(sampleUrls), 'auto-monitor')
    await createEmailScan(pickRandom(sampleEmails), 'auto-monitor')
  }

  run().catch(console.error)
  return setInterval(() => {
    run().catch(console.error)
  }, 5000)
}
