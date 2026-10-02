// Isolated unpacked-extension checks. Synthetic web pages, real extension code,
// real local backend; never touches the user's browser profile or production data.
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdtemp, cp, readFile, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import os from 'node:os'
import net from 'node:net'

const root = fileURLToPath(new URL('../../', import.meta.url))
const artifacts = await mkdtemp(path.join(os.tmpdir(), 'tracking-extension-audit-'))
const require = createRequire(path.join(process.env.E2E_PLAYWRIGHT_NODE_MODULES, '@playwright/test/package.json'))
const { chromium } = require('@playwright/test')
const report = { startedAt: new Date().toISOString(), cases: [], limitations: ['Synthetic Google/Gmail page fixtures, not signed-in live services.', 'activeTab user gesture is not simulated; denial without a gesture is tested.'] }
let browser, backend
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
async function until(fn, timeout = 15000) {
  const deadline = Date.now() + timeout
  while (Date.now() < deadline) { const result = await fn(); if (result) return result; await delay(150) }
  throw new Error('Condition timed out')
}
async function check(name, run) {
  try { const evidence = await run(); report.cases.push({ name, status: 'passed', evidence }); console.log(`PASS: ${name}`) }
  catch (error) { report.cases.push({ name, status: 'failed', error: error.message }); console.log(`FAIL: ${name}: ${error.message}`) }
}
try {
  const socket = net.createServer().listen(0, '127.0.0.1')
  await once(socket, 'listening')
  const port = socket.address().port
  await new Promise((resolve) => socket.close(resolve))
  const origin = `http://127.0.0.1:${port}`
  const osVars = Object.fromEntries(Object.entries(process.env).filter(([key]) => /^(path|systemroot|windir|comspec|pathext|temp|tmp|userprofile|appdata|localappdata)$/i.test(key)))
  backend = spawn(process.execPath, [path.join(root, 'backend/server.js')], { cwd: artifacts, windowsHide: true,
    env: { ...osVars, NODE_ENV: 'production', PORT: String(port), DATABASE_URL: '', DATABASE_PATH: path.join(artifacts, 'test.sqlite'), PUBLIC_DEPLOYMENT: 'true', REPUTATION_ENABLED: 'false', SMTP_ENABLED: 'false', AUTO_MONITOR: 'false', CORS_ALLOW_CHROME_EXTENSIONS: 'true' }, stdio: ['ignore', 'pipe', 'pipe'] })
  let log = ''
  backend.stdout.on('data', (chunk) => { log += chunk })
  backend.stderr.on('data', (chunk) => { log += chunk })
  await until(async () => { try { return (await fetch(`${origin}/api/health`)).ok } catch { return false } })
  const extension = path.join(artifacts, 'extension')
  await cp(path.join(root, 'browser-extension'), extension, { recursive: true })
  const manifest = JSON.parse(await readFile(path.join(extension, 'manifest.json'), 'utf8'))
  report.permissions = manifest.permissions
  report.originalHostPermissions = manifest.host_permissions
  // Redirect only the existing backend grant to an isolated loopback service.
  manifest.host_permissions = ['http://127.0.0.1/*']
  manifest.content_scripts.find((script) => script.js.includes('app-bridge.js')).matches = [origin + '/*']
  await writeFile(path.join(extension, 'manifest.json'), JSON.stringify(manifest))
  await writeFile(path.join(extension, 'config.js'), `const TRACKING_THREATS_CONFIG = ${JSON.stringify({ API_BASE_URL: origin, APP_URL: origin + '/' })}`)
  browser = await chromium.launchPersistentContext(path.join(artifacts, 'profile'), {
    executablePath: process.env.E2E_BROWSER_EXECUTABLE, headless: true,
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
  })
  report.browser = browser.browser()?.version()
  browser.setDefaultTimeout(15000)
  const worker = browser.serviceWorkers()[0] ?? await browser.waitForEvent('serviceworker', { timeout: 15000 })
  report.extensionId = new URL(worker.url()).host
  report.cases.push({ name: 'Manifest V3 service worker loads', status: 'passed' })
  await browser.route('**/*', (route) => {
    const url = new URL(route.request().url())
    if (url.origin === origin || url.protocol === 'chrome-extension:') return route.continue()
    let body = '<!doctype html><title>Audit page</title><h1>Audit page</h1><p>Ordinary meeting notes.</p>'
    if (url.hostname === 'www.google.com') body = '<!doctype html><title>Search fixture</title><div id="search"><div class="g"><a href="https://paypal.audit-fixture.test/verify-password"><h3>Account result fixture</h3></a></div></div>'
    if (url.hostname === 'mail.google.com') body = '<!doctype html><title>Mail fixture</title><div role="main"><h2 class="hP">Meeting notes</h2><span email="sender@example.test">Sender</span><div class="a3s aiL">The meeting starts tomorrow at noon. Please bring the agenda.</div></div>'
    return route.fulfill({ status: 200, contentType: 'text/html', body })
  })
  const page = await browser.newPage()
  const pageErrors = []
  page.on('pageerror', (error) => pageErrors.push(error.message))
  await check('automatic URL navigation, storage and badge', async () => {
    await page.goto('https://audit-fixture.test/ordinary')
    const status = await until(() => worker.evaluate(async () => { const { threattrackStatus: s } = await chrome.storage.local.get('threattrackStatus'); return s?.lastUrl?.includes('/ordinary') && s.ok ? s : null }))
    assert.equal(status.lastStatus, 'Safe')
    const badge = await worker.evaluate(() => chrome.action.getBadgeText({}))
    assert.equal(badge, '?', 'Offline provider coverage must not get an OK badge')
    return { score: status.lastScore, badge, coverage: status.coverage.status }
  })
  await check('activeTab denies rendered-page injection without user invocation', async () => {
    const result = await worker.evaluate(async () => {
      const [tab] = await chrome.tabs.query({ url: 'https://audit-fixture.test/*' })
      try { await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: () => document.title }); return 'unexpectedly allowed' }
      catch (error) { return error.message }
    })
    assert.match(result, /permission|access/i)
    return result
  })
  await check('History API navigation triggers automatic scanning', async () => {
    await page.evaluate(() => history.pushState({}, '', '/spa-next'))
    return until(() => worker.evaluate(async () => { const { threattrackStatus: s } = await chrome.storage.local.get('threattrackStatus'); return s?.lastUrl?.includes('/spa-next') && s.ok ? { status: s.lastStatus, score: s.lastScore } : null }))
  })
  await check('dangerous navigation redirects to warning and installs a block rule', async () => {
    await page.goto('https://paypal.audit-danger.test/verify-password').catch(() => {})
    await until(() => page.url().includes('/blocked.html'))
    const rules = await worker.evaluate(() => chrome.declarativeNetRequest.getDynamicRules())
    assert.ok(rules.some((rule) => rule.action.type === 'block'))
    return { warningPage: true, rules: rules.length }
  })
  await check('blocked details opens matching saved scan through real credential bridge', async () => {
    await until(async () => (await page.locator('#details-link').getAttribute('href'))?.includes('client='))
    const scanId = new URL(page.url()).searchParams.get('scan')
    assert.ok(scanId)
    const opened = browser.waitForEvent('page')
    await page.locator('#details-link').click()
    const historyPage = await opened
    await historyPage.locator(`#scan-${scanId}`).waitFor({ timeout: 25000 })
    await historyPage.close()
    assert.ok(!pageErrors.some((error) => error.includes("reading 'style'")), 'Warning page must not crash on missing popup elements')
    return { scanId, pageErrors: [...pageErrors] }
  })
  await check('blocked visit recovers after saved history was removed', async () => {
    const oldWarningUrl = page.url()
    await worker.evaluate(async (origin) => {
      const stored = await chrome.storage.local.get(['threattrackClientId', 'threattrackClientToken'])
      const response = await fetch(`${origin}/api/public/activity/${stored.threattrackClientId}`, {
        method: 'DELETE', headers: { 'x-client-token': stored.threattrackClientToken },
      })
      if (!response.ok) throw new Error(`Fixture cleanup failed: ${response.status}`)
    }, origin)
    await page.goto(oldWarningUrl)
    await until(async () => {
      const href = await page.locator('#details-link').getAttribute('href')
      return href?.includes('client=') && new URL(href).searchParams.get('scan') !== new URL(oldWarningUrl).searchParams.get('scan')
    })
    const href = await page.locator('#details-link').getAttribute('href')
    const scanId = new URL(href).searchParams.get('scan')
    assert.ok(scanId)
    const opened = browser.waitForEvent('page')
    await page.locator('#details-link').click()
    const historyPage = await opened
    await historyPage.locator(`#scan-${scanId}`).waitFor({ timeout: 25000 })
    await historyPage.getByRole('button', { name: 'Monitor', exact: true }).first().click()
    await historyPage.getByText('browser-extension', { exact: false }).first().waitFor()
    await historyPage.getByText('https://paypal.audit-danger.test/verify-password', { exact: true }).first().waitFor()
    await historyPage.close()
    return { recoveredScanId: scanId, liveMonitor: true }
  })
  await check('persistent block-rule navigation saves a fresh automatic visit', async () => {
    const previous = new URL(await page.locator('#details-link').getAttribute('href')).searchParams.get('scan')
    await page.goto('https://paypal.audit-danger.test/verify-password').catch(() => {})
    await until(() => page.url().includes('/blocked.html'))
    const href = await until(async () => {
      const link = await page.locator('#details-link').getAttribute('href')
      return link?.includes('client=') && new URL(link).searchParams.get('scan') !== previous ? link : null
    })
    return { newScanId: new URL(href).searchParams.get('scan') }
  })
  await check('history reports sync failure and recovers automatically', async () => {
    const historyPage = await browser.newPage()
    const href = await page.locator('#details-link').getAttribute('href')
    await historyPage.route('**/api/public/activity/*', (route) => route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'Fixture connection outage' }) }))
    await historyPage.goto(href)
    await historyPage.getByRole('alert').filter({ hasText: 'History could not be synced' }).waitFor({ timeout: 20000 })
    await historyPage.unroute('**/api/public/activity/*')
    await historyPage.locator(`#scan-${new URL(href).searchParams.get('scan')}`).waitFor({ timeout: 20000 })
    await until(async () => (await historyPage.getByRole('alert').filter({ hasText: 'History could not be synced' }).count()) === 0)
    await historyPage.close()
    return { visibleError: true, recovered: true }
  })
  await check('Google matched content script scans fixture result automatically', async () => {
    await page.goto('https://www.google.com/search?q=tracking-audit')
    await page.locator('.threattrack-result-badge').first().waitFor({ timeout: 20000 })
    return { badge: await page.locator('.threattrack-result-badge').first().innerText() }
  })
  await check('Gmail matched content script presents email consent gate', async () => {
    await page.goto('https://mail.google.com/mail/u/0/')
    await page.locator('#threattrack-email-consent').waitFor({ timeout: 15000 })
    return { consentGate: true }
  })
  await check('Gmail fixture scans through backend after explicit consent', async () => {
    await page.locator('#threattrack-email-consent input[type=checkbox]').check()
    await page.getByRole('button', { name: 'I Agree and Enable Email Scanning', exact: true }).click()
    return until(() => worker.evaluate(async () => {
      const { threattrackStatus: status } = await chrome.storage.local.get('threattrackStatus')
      return status?.lastUrl === 'Email scan' && status.ok ? { score: status.lastScore, status: status.lastStatus } : null
    }), 20000)
  })
  await check('popup displays saved status', async () => {
    const popup = await browser.newPage()
    await popup.goto(`chrome-extension://${report.extensionId}/popup.html`)
    await until(async () => (await popup.locator('#pill').innerText()) !== 'Ready')
    const text = await popup.locator('#pill').innerText()
    await popup.screenshot({ path: path.join(artifacts, 'popup.png') })
    await popup.close()
    return { text }
  })
  await writeFile(path.join(artifacts, 'backend.log'), log)
} catch (error) { report.infrastructureError = error.message; console.error(error.message) }
finally {
  await browser?.close().catch(() => {})
  if (backend?.exitCode === null) { const stopped = once(backend, 'exit'); backend.kill(); await stopped }
  report.finishedAt = new Date().toISOString()
  report.passed = report.cases.filter((item) => item.status === 'passed').length
  report.failed = report.cases.filter((item) => item.status === 'failed').length
  report.artifacts = artifacts
  await writeFile(path.join(artifacts, 'results.json'), JSON.stringify(report, null, 2))
  await writeFile(path.join(root, 'tests/e2e/results/2026-10-02-extension-history.json'), JSON.stringify(report, null, 2))
  console.log(JSON.stringify({ passed: report.passed, failed: report.failed, infrastructureError: report.infrastructureError, artifacts }))
  if (report.failed || report.infrastructureError) process.exitCode = 1
}
