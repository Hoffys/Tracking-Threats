import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { existsSync, readFileSync } from 'node:fs'
import { mkdtemp, writeFile } from 'node:fs/promises'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import vm from 'node:vm'
import { setTimeout as delay } from 'node:timers/promises'
import { readSearchPreview } from '../../src/utils/searchPreview.js'

// Deliberately separate from node --test: this requires a reviewed public build.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const args = new Set(process.argv.slice(2))
const checkOnly = args.has('--check')
const ready = args.has('--build-ready')
const report = { startedAt: new Date().toISOString(), status: 'not-run', cases: [] }
let backend
let browser
let artifacts
let backendLog = ''

function dependencies() {
  const modules = process.env.E2E_PLAYWRIGHT_NODE_MODULES
  if (!modules || !path.isAbsolute(modules)) {
    throw new Error('Set E2E_PLAYWRIGHT_NODE_MODULES to the absolute node_modules directory of a TEMP @playwright/test install. See docs/browser-acceptance.md.')
  }
  const entry = path.join(modules, '@playwright/test/package.json')
  if (!existsSync(entry)) throw new Error(`External Playwright missing: ${entry}. No browser checks ran.`)
  const externalRequire = createRequire(entry)
  const { chromium, expect } = externalRequire('@playwright/test')
  const executablePath = process.env.E2E_BROWSER_EXECUTABLE
  if (!executablePath || !path.isAbsolute(executablePath) || !existsSync(executablePath)) {
    throw new Error('Set E2E_BROWSER_EXECUTABLE to an installed Chromium/Edge executable. No browser checks ran.')
  }
  return { chromium, expect: expect.configure({ timeout: 12000 }), executablePath,
    version: JSON.parse(readFileSync(entry, 'utf8')).version }
}

async function freePort() {
  const server = net.createServer()
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = server.address().port
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
  return port
}

function backendEnvironment(port) {
  // Start outside the checkout so loadEnvFile cannot load the developer's .env.
  // Only OS runtime variables are inherited; never inherit provider credentials.
  const allowed = /^(path|systemroot|windir|comspec|pathext|temp|tmp|userprofile|appdata|localappdata|home|lang)$/i
  return {
    ...Object.fromEntries(Object.entries(process.env).filter(([key]) => allowed.test(key))),
    NODE_OPTIONS: '--use-system-ca', NODE_ENV: 'production', PORT: String(port),
    DATABASE_URL: '', DATABASE_PATH: path.join(artifacts, 'acceptance.sqlite'),
    PUBLIC_DEPLOYMENT: 'true', STORE_SCAN_CONTENT: 'false', AUTO_MONITOR: 'false',
    SMTP_ENABLED: 'false', SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '', SMTP_FROM: '',
    RESEND_API_KEY: '', RESEND_FROM: '', REPUTATION_ENABLED: 'false',
    URLHAUS_AUTH_KEY: '', VIRUSTOTAL_API_KEY: '', GOOGLE_SAFE_BROWSING_API_KEY: '',
    PHISHTANK_APP_KEY: '', ABUSEIPDB_API_KEY: '',
    ADMIN_API_TOKEN: 'isolated-browser-audit-admin',
    FRONTEND_ORIGIN: `http://127.0.0.1:${port}`, CORS_ALLOW_NO_ORIGIN: 'true',
  }
}

async function startBackend() {
  const source = readFileSync(path.join(root, 'backend/services/threatIntel.js'), 'utf8')
  assert.match(source, /REPUTATION_ENABLED/, 'Backend must implement the offline reputation switch before running.')
  assert.ok(existsSync(path.join(root, 'dist/index.html')), 'Missing dist/index.html; main must build the public frontend first.')
  const port = await freePort()
  const origin = `http://127.0.0.1:${port}`
  backend = spawn(process.execPath, [path.join(root, 'backend/server.js')], {
    cwd: artifacts, env: backendEnvironment(port), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
  })
  backend.stdout.on('data', (chunk) => { backendLog += chunk })
  backend.stderr.on('data', (chunk) => { backendLog += chunk })
  let launchError
  backend.on('error', (error) => { launchError = error })
  for (let i = 0; i < 100; i++) {
    if (launchError) throw launchError
    if (backend.exitCode !== null) throw new Error(`Isolated backend exited (${backend.exitCode}). ${backendLog}`)
    try {
      const response = await fetch(`${origin}/api/health`, { signal: AbortSignal.timeout(500) })
      const health = await response.json()
      if (response.ok && health.ok) {
        assert.equal(health.repository, 'sqlite', 'Acceptance must use temporary SQLite.')
        return origin
      }
    } catch { /* The newly spawned server may still be initializing. */ }
    await delay(200)
  }
  throw new Error(`Isolated backend did not become healthy. ${backendLog}`)
}

function extensionPreviewUrl(origin, snapshot) {
  // Execute the extension's actual URL serializer, as its existing unit tests do.
  // This is not a claim to have loaded the extension into the browser.
  const source = readFileSync(path.join(root, 'browser-extension/google-results.js'), 'utf8')
  const end = source.indexOf('function addBadge(')
  assert.ok(end > 0, 'Extension preview serializer boundary changed; update harness.')
  const sandbox = { URL, URLSearchParams, TRACKING_THREATS_CONFIG: { APP_URL: origin } }
  vm.runInNewContext(source.slice(0, end), sandbox, { timeout: 1000 })
  const href = sandbox.getDetailsUrl(snapshot.target, `${origin}/?scan=old&blocked=old`, snapshot)
  assert.deepEqual(readSearchPreview(href), snapshot, 'Preview serializer/parser must retain every supplied display field exactly.')
  const url = new URL(href)
  assert.equal(url.searchParams.has('scan'), false)
  assert.equal(url.searchParams.has('blocked'), false)
  assert.equal(url.search.includes('example.com'), false, 'Preview target belongs in the fragment.')
  return href
}

async function run() {
  const { chromium, expect, executablePath, version } = dependencies()
  if (checkOnly) {
    console.log(JSON.stringify({ status: 'prerequisites-ready', playwright: version, executablePath,
      browserLaunched: false, backendStarted: false, acceptanceRun: false }, null, 2))
    return
  }
  if (!ready) throw new Error('UI checks are gated. Wait for main to confirm the public build is ready, then pass --build-ready. No browser checks ran.')
  artifacts = await mkdtemp(path.join(os.tmpdir(), 'tracking-threats-browser-acceptance-'))
  console.log(`Artifacts: ${artifacts}`)
  report.artifacts = artifacts
  report.playwright = version
  report.executablePath = executablePath
  report.buildSha256 = createHash('sha256').update(readFileSync(path.join(root, 'dist/index.html'))).digest('hex')
  const origin = await startBackend()
  report.origin = origin
  browser = await chromium.launch({ executablePath, headless: process.env.E2E_HEADED !== 'true' })
  report.browser = browser.version()
  const cases = []
  const test = (name, fn) => cases.push({ name, fn })

  const output = (page) => page.locator('section').filter({ has: page.getByRole('heading', { name: 'Scan output', exact: true }) })
  const row = (page, scan) => page.locator(`[id="scan-${scan.id}"]`)
  const apiResponse = (page, method, pathname) => page.waitForResponse((res) =>
    res.request().method() === method && new URL(res.url()).pathname === pathname)
  const screenshot = (page, name) => page.screenshot({ path: path.join(artifacts, `${name}.png`), fullPage: true })
  async function responseJson(pending) {
    const response = await pending
    if (!response.ok()) {
      let body = '<response body unavailable>'
      try { body = await response.text() } catch { /* Navigation can dispose the response body. */ }
      assert.fail(`${response.request().method()} ${new URL(response.url()).pathname}: ${response.status()} ${body}`)
    }
    return response.json()
  }
  async function open(page, route, reload = false) {
    const activity = page.waitForResponse((res) => res.request().method() === 'GET' && new URL(res.url()).pathname.startsWith('/api/public/activity/'))
    const settings = apiResponse(page, 'GET', '/api/notification-settings')
    await (reload ? page.reload() : page.goto(`${origin}/?page=${route}`))
    await Promise.all([responseJson(activity), responseJson(settings)])
  }
  async function scanSms(page, content, target) {
    await open(page, 'manual')
    await page.getByRole('button', { name: 'SMS', exact: true }).click()
    await page.getByLabel('Sender or subject', { exact: true }).fill(target)
    await page.getByLabel('SMS content', { exact: true }).fill(content)
    await expect(page.getByRole('button', { name: 'Run Scan', exact: true })).toBeDisabled()
    await page.getByRole('checkbox', { name: /I am authorized to scan this item/ }).check()
    const pending = apiResponse(page, 'POST', '/api/scan/message')
    await page.getByRole('button', { name: 'Run Scan', exact: true }).click()
    const scan = await responseJson(pending)
    assert.ok(scan.id, 'A real UI submission must create a saved scan.')
    await expect(output(page)).toContainText(`Safety score ${scan.score}/100`)
    return scan
  }
  async function persist(page, scan) {
    await open(page, 'history')
    await expect(row(page, scan)).toBeVisible()
    await expect(row(page, scan)).toContainText(`Safety score ${scan.score}/100`)
    await open(page, 'history', true)
    await expect(row(page, scan)).toBeVisible()
    await expect(row(page, scan)).toContainText(scan.summary)
    return row(page, scan)
  }

  test('benign SMS and history survive reload', async ({ page, evidence }) => {
    const scan = await scanSms(page, 'Hi Sam, lunch is at noon in the usual cafe. See you there!', 'E2E lunch reminder')
    evidence.scan = scan
    assert.equal(scan.status, 'Safe', 'Benign conversational SMS should have no strong indicators.')
    assert.ok(scan.score >= 80)
    await expect(output(page)).toContainText('Local analysis only')
    await expect(output(page)).toContainText('not a calibrated probability')
    await screenshot(page, 'benign-sms-output')
    await persist(page, scan)
  })

  test('direct credential SMS shows risk without claiming automatic blocking', async ({ page, evidence }) => {
    const scan = await scanSms(page, 'Reply with your password and OTP now to verify your account.', 'E2E fictional credential request')
    evidence.scan = scan
    assert.notEqual(scan.status, 'Safe', 'A direct password and OTP request must be flagged.')
    await expect(output(page)).toContainText(/Risk detected|Caution/)
    await expect(output(page)).toContainText(/review recommended|Review result/i)
    const text = await output(page).innerText()
    // Match affirmative claims, not the explanation's "does not ... prove that access was blocked".
    assert.doesNotMatch(text, /automatically blocked|(?:^|\n)\s*Access (?:has been|was) blocked|Response:\s*Blocked|System response\s*Blocked/i)
    if (scan.blocked) await expect(output(page)).toContainText('A manual scan does not itself block access.')
    await screenshot(page, 'credential-sms-output')
    await persist(page, scan)
  })

  test('offline URL explicitly discloses incomplete coverage and persists it', async ({ page, evidence }) => {
    await open(page, 'manual')
    await page.getByLabel('URL to scan', { exact: true }).fill('https://example.com/')
    await page.getByRole('checkbox', { name: /I am authorized to scan this item/ }).check()
    const pending = apiResponse(page, 'POST', '/api/scan/url')
    await page.getByRole('button', { name: 'Run Scan', exact: true }).click()
    const scan = await responseJson(pending)
    evidence.scan = scan
    assert.equal(scan.coverage?.checkedProviders, 0)
    assert.notEqual(scan.coverage.status, 'complete')
    await expect(output(page)).toContainText('Appears safe')
    await expect(output(page)).toContainText('Scan finished.')
    await expect(output(page)).toContainText('No further checks are pending.')
    await expect(output(page)).toContainText(/Reputation checks were unavailable|Local analysis only/)
    await expect(output(page)).toContainText('not a guarantee of safety')
    await expect(output(page).getByText('Safe', { exact: true })).toHaveCount(0)
    await expect(output(page)).toContainText(/Not checked|skipped|disabled/i)
    await screenshot(page, 'offline-url-output')
    const saved = await persist(page, scan)
    await expect(saved).toContainText('Appears safe')
    await expect(saved).toContainText(`0/${scan.coverage.totalProviders} providers checked`)
  })

  test('settings persist and Delete My Data removes this client data', async ({ page, evidence }) => {
    const scan = await scanSms(page, 'Meeting starts at ten. Bring your notes.', 'E2E settings sample')
    await open(page, 'settings')
    await page.getByPlaceholder('TrackingThreats@example.com').fill('acceptance@example.invalid')
    await page.getByRole('button', { name: 'Add Email', exact: true }).click()
    await page.getByRole('checkbox', { name: /Email scanned records/ }).uncheck()
    await page.getByRole('checkbox', { name: /Email history digest/ }).uncheck()
    const save = apiResponse(page, 'PUT', '/api/notification-settings')
    await page.getByRole('button', { name: 'Save Settings', exact: true }).click()
    evidence.saved = await responseJson(save)
    await expect(page.getByText('Settings saved', { exact: true })).toBeVisible()
    await open(page, 'settings', true)
    await expect(page.getByText('acceptance@example.invalid', { exact: true })).toBeVisible()
    await expect(page.getByRole('checkbox', { name: /Email scanned records/ })).not.toBeChecked()
    await expect(page.getByRole('checkbox', { name: /Email history digest/ })).not.toBeChecked()
    await expect(page.getByRole('button', { name: 'Send History Digest', exact: true })).toBeDisabled()
    await screenshot(page, 'settings-persisted-before-deletion')
    const deletion = page.waitForResponse((res) => res.request().method() === 'DELETE' && new URL(res.url()).pathname.startsWith('/api/public/data/'))
    page.once('dialog', (dialog) => dialog.accept())
    await page.getByRole('button', { name: 'Delete My Data', exact: true }).click()
    evidence.deleted = await responseJson(deletion)
    await expect(page.getByText('Client data deleted.', { exact: true })).toBeVisible()
    await open(page, 'settings', true)
    await expect(page.getByText('acceptance@example.invalid', { exact: true })).toHaveCount(0)
    await open(page, 'history')
    await expect(row(page, scan)).toHaveCount(0)
    await expect(page.locator('article[id^="scan-"]')).toHaveCount(0)
  })

  test('Delete Scan History persists and preserves a second browser client', async ({ page, newPage, evidence }) => {
    const own = await scanSms(page, 'See you at the library tomorrow.', 'E2E first client')
    const otherPage = await newPage()
    const other = await scanSms(otherPage, 'Dinner is ready at six.', 'E2E second client')
    await persist(otherPage, other)
    await persist(page, own)
    await expect(row(page, other)).toHaveCount(0)
    const deletion = page.waitForResponse((res) => res.request().method() === 'DELETE' && new URL(res.url()).pathname.startsWith('/api/public/activity/'))
    page.once('dialog', (dialog) => dialog.accept())
    await page.getByRole('button', { name: 'Delete Scan History', exact: true }).click()
    evidence.deleted = await responseJson(deletion)
    await expect(row(page, own)).toHaveCount(0)
    await open(page, 'history', true)
    await expect(page.locator('article[id^="scan-"]')).toHaveCount(0)
    await expect(page.getByText('No saved scans loaded. Automatic browser scans, email scans, and manual scans appear here when synced with this browser.', { exact: true })).toBeVisible()
    await open(otherPage, 'history', true)
    await expect(row(otherPage, other)).toBeVisible()
    evidence.preservedOtherScanId = other.id
  })

  for (const [status, checkedProviders, totalProviders, label] of [
    ['partial', 1, 3, 'Some reputation checks were unavailable or skipped'], ['unavailable', 0, 3, 'Reputation checks were unavailable'],
    ['local-only', 0, 0, 'Local analysis only'], ['legacy', 0, 0, 'Check details were not recorded'],
  ]) {
    test(`${status} preview roundtrip stays exact and creates no saved scan`, async ({ page, evidence }) => {
      await open(page, 'history')
      await expect(page.locator('article[id^="scan-"]')).toHaveCount(0)
      const snapshot = {
        target: `https://example.com/preview?case=${status}&note=%E2%9C%93`,
        status: 'Safe', score: 87, summary: `E2E ${status} preview — exact & unchanged.`,
        warningSigns: ['Fixture warning: café & <text>'], recommendations: ['Review this fixture before proceeding.'],
        categories: ['gambling-content'], categoryWarnings: ['Fixture content category is not phishing evidence.'],
        ...(status === 'legacy' ? {} : { coverage: { status, checkedProviders, totalProviders,
          limitations: ['Fixture coverage limitation: providers unavailable.'], linksChecked: 1, totalLinks: 2 } }),
      }
      const href = extensionPreviewUrl(origin, snapshot)
      evidence.snapshot = snapshot
      const scans = []
      page.on('request', (req) => {
        if (req.method() === 'POST' && new URL(req.url()).pathname.startsWith('/api/scan/')) scans.push(req.url())
      })
      await page.goto(href)
      const preview = page.locator('section').filter({ has: page.getByText('Search result preview', { exact: true }) })
      await expect(preview).toBeVisible()
      await expect(preview.getByText(snapshot.target, { exact: true })).toBeVisible()
      await expect(preview.getByText(snapshot.summary, { exact: true })).toBeVisible()
      await expect(preview).toContainText('Safety score 87/100')
      for (const item of [...snapshot.warningSigns, ...snapshot.recommendations, ...snapshot.categoryWarnings]) {
        await expect(preview.getByText(item, { exact: true }).first()).toBeVisible()
      }
      await expect(preview).toContainText(label)
      await expect(preview).toContainText('Content warning - separate from phishing')
      await expect(preview).toContainText('content warning found')
      await expect(preview).toContainText('These content categories do not establish phishing.')
      await expect(preview).toContainText('It has not been saved to scan history.')
      if (snapshot.coverage) {
        await expect(preview).toContainText(`${checkedProviders}/${totalProviders} providers checked; 1/2 links checked.`)
        await expect(preview).toContainText(snapshot.coverage.limitations[0])
      }
      assert.deepEqual(readSearchPreview(page.url()), snapshot)
      await page.reload()
      await expect(preview).toContainText(snapshot.summary)
      await expect(preview).toContainText(label)
      assert.deepEqual(readSearchPreview(page.url()), snapshot)
      assert.equal(scans.length, 0, 'Preview must never submit a scan or rescan the target.')
      await screenshot(page, `preview-${status}-after-reload`)
      await open(page, 'history')
      await expect(page.locator('article[id^="scan-"]')).toHaveCount(0)
      evidence.scanPosts = scans.length
    })
  }

  test('malformed preview reports invalid data without a saved result', async ({ page }) => {
    await open(page, 'history')
    await page.goto(`${origin}/?page=history&preview=1#preview=not-json`)
    await expect(page.getByText(/This preview link is incomplete or invalid/)).toBeVisible()
    await expect(page.locator('article[id^="scan-"]')).toHaveCount(0)
  })

  test('phone, tablet and short laptop navigation plus Learn certificates stay usable', async ({ newPage, evidence }) => {
    const page = await newPage({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true })
    await open(page, 'dashboard')
    await expect(page.getByRole('navigation', { name: 'Mobile navigation' })).toBeHidden()
    await page.getByRole('button', { name: 'Show navigation' }).click()
    await expect(page.getByRole('navigation', { name: 'Mobile navigation' })).toBeVisible()
    await page.getByRole('navigation', { name: 'Mobile navigation' }).getByRole('button', { name: 'Scan', exact: true }).click()
    await expect(page.getByRole('navigation', { name: 'Mobile navigation' })).toBeHidden()
    await expect(page.getByRole('heading', { name: /Scan a URL/i })).toBeVisible()
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    assert.ok(overflow <= 1, `Mobile page overflows horizontally by ${overflow}px`)
    evidence.phone = await page.evaluate(() => ({ width: innerWidth, height: innerHeight, overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth }))
    await screenshot(page, 'mobile-manual-scan')

    const tablet = await newPage({ viewport: { width: 820, height: 1180 }, hasTouch: true })
    await open(tablet, 'dashboard')
    await expect(tablet.getByRole('navigation', { name: 'Mobile navigation' })).toBeVisible()
    const tabletOverflow = await tablet.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    assert.ok(tabletOverflow <= 1, `Tablet page overflows horizontally by ${tabletOverflow}px`)
    evidence.tablet = { width: 820, height: 1180, overflow: tabletOverflow }

    const laptop = await newPage({ viewport: { width: 1366, height: 650 } })
    await open(laptop, 'dashboard')
    const sidebar = laptop.locator('aside').first()
    await expect(sidebar).toBeVisible()
    const sidebarMetrics = await sidebar.evaluate((element) => {
      const style = getComputedStyle(element)
      element.scrollTop = element.scrollHeight
      return {
        overflowY: style.overflowY,
        clientHeight: element.clientHeight,
        scrollHeight: element.scrollHeight,
        reachedBottom: Math.ceil(element.scrollTop + element.clientHeight) >= element.scrollHeight,
      }
    })
    assert.equal(sidebarMetrics.overflowY, 'auto')
    assert.ok(sidebarMetrics.scrollHeight > sidebarMetrics.clientHeight, 'Short laptop sidebar should need vertical scrolling.')
    assert.equal(sidebarMetrics.reachedBottom, true)
    evidence.shortLaptop = { width: 1366, height: 650, ...sidebarMetrics }
    const levelModules = {
      Intermediate: [
        'Password Defense',
        'Multi-Factor Authentication',
        'File & Attachment Safety',
        'Social Engineering Tactics',
        'Report Quality',
        'Browser Extension Safety',
      ],
      Advanced: [
        'Incident Response',
        'Threat Triage',
        'Domain Investigation',
        'Attachment Analysis',
        'Security Coaching',
        'Policy & Allowlist Review',
      ],
    }
    const completeLevel = async (level) => {
      await laptop.getByRole('button', { name: level, exact: true }).click()
      for (const title of levelModules[level]) {
        const moduleCard = laptop.getByRole('button').filter({
          has: laptop.getByRole('heading', { name: title, exact: true }),
        })
        await moduleCard.click()
        await laptop.getByRole('button', { name: 'Mark module complete', exact: true }).click()
        await laptop.getByRole('button', { name: 'Close selected module', exact: true }).click()
      }
    }

    await open(laptop, 'learn')
    await expect(laptop.getByRole('heading', { name: 'Learn Modules', exact: true })).toBeVisible()
    await completeLevel('Intermediate')

    const intermediateCertificate = laptop.getByRole('region', { name: 'Your Intermediate certificate is ready!' })
    await expect(intermediateCertificate).toBeVisible()
    await expect(intermediateCertificate.getByRole('heading', { name: 'Intermediate Security Awareness', exact: true })).toBeVisible()
    await intermediateCertificate.getByLabel('Name on certificate').fill('Intermediate Learner')
    await expect(intermediateCertificate.getByRole('button', { name: 'Download certificate (PNG)', exact: true })).toBeEnabled()
    await expect(laptop.getByRole('region', { name: 'Your Beginner certificate is ready!' })).toHaveCount(0)

    await completeLevel('Advanced')
    const advancedCertificate = laptop.getByRole('region', { name: 'Your Advanced certificate is ready!' })
    await expect(advancedCertificate).toBeVisible()
    await expect(advancedCertificate.getByRole('heading', { name: 'Advanced Security Awareness', exact: true })).toBeVisible()
    await advancedCertificate.getByLabel('Name on certificate').fill('Advanced Learner')
    await expect(advancedCertificate.getByRole('button', { name: 'Download certificate (PNG)', exact: true })).toBeEnabled()
    await expect(laptop.getByText('6/6 modules complete', { exact: true })).toHaveCount(2)
    await laptop.screenshot({ path: path.join(artifacts, 'learn-intermediate-advanced-certificates.png'), fullPage: true })

    evidence.certificates = {
      intermediateModules: levelModules.Intermediate.length,
      advancedModules: levelModules.Advanced.length,
      beginnerRemainedLockedWithoutQuiz: true,
    }
  })

  test('admin clients filter linked and legacy records without duplicating heartbeats', async ({ page, evidence }) => {
    const jsonRequest = async (pathname, { method = 'GET', token = '', body } = {}) => {
      const response = await fetch(`${origin}${pathname}`, {
        method,
        headers: {
          ...(body ? { 'Content-Type': 'application/json' } : {}),
          ...(token ? { 'X-Client-Token': token } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      })
      const payload = await response.json()
      assert.ok(response.ok, `${method} ${pathname}: ${response.status} ${JSON.stringify(payload)}`)
      return payload
    }

    const linked = await jsonRequest('/api/public/clients', { method: 'POST' })
    await jsonRequest('/api/public/devices', {
      method: 'POST', token: linked.token,
      body: { clientId: linked.clientId, deviceName: 'Bryan PC', browserName: 'Brave' },
    })
    for (let index = 0; index < 2; index += 1) {
      await jsonRequest('/api/public/extension/heartbeat', {
        method: 'POST', token: linked.token,
        body: { clientId: linked.clientId, version: '1.0.31', browserName: 'Brave' },
      })
    }
    await jsonRequest('/api/scan/message', {
      method: 'POST', token: linked.token,
      body: {
        clientId: linked.clientId,
        target: 'Admin clients acceptance fixture',
        message: 'Meeting starts at noon.',
        source: 'api',
        privacyAccepted: true,
      },
    })
    const adminHeaders = { Authorization: 'Bearer isolated-browser-audit-admin' }
    const listResponse = await fetch(`${origin}/api/admin/clients`, { headers: adminHeaders })
    assert.equal(listResponse.status, 200)
    const beforeUi = await listResponse.json()
    assert.equal(beforeUi.filter((client) => client.clientId === linked.clientId).length, 1)
    const linkedRecord = beforeUi.find((client) => client.clientId === linked.clientId)
    assert.equal(linkedRecord.deviceName, 'Bryan PC')
    assert.equal(linkedRecord.browserName, 'Brave')
    assert.equal(linkedRecord.extensionVersion, '1.0.31')
    assert.ok(linkedRecord.extensionLastSeenAt)

    await open(page, 'admin')
    await page.getByLabel('Admin Only Access Key').fill('isolated-browser-audit-admin')
    await page.getByRole('button', { name: 'Sign in', exact: true }).click()
    const afterPageResponse = await fetch(`${origin}/api/admin/clients`, { headers: adminHeaders })
    assert.equal(afterPageResponse.status, 200)
    const afterPage = await afterPageResponse.json()
    const unlinked = afterPage.find((client) => client.clientId !== linked.clientId && !client.deviceId)
    assert.ok(unlinked, 'Acceptance needs an existing unlinked browser client.')

    const linkedFilter = page.getByRole('button', { name: /Linked \/ Active \(\d+\)/ })
    const allFilter = page.getByRole('button', { name: /All Clients \(\d+\)/ })
    const legacyFilter = page.getByRole('button', { name: /Legacy \/ Unlinked \(\d+\)/ })
    await expect(linkedFilter).toHaveAttribute('aria-pressed', 'true')
    await expect(page.getByRole('button', { name: linked.clientId, exact: true })).toBeVisible()
    await expect(page.getByRole('button', { name: unlinked.clientId, exact: true })).toHaveCount(0)

    const linkedRow = page.getByRole('row').filter({ has: page.getByRole('button', { name: linked.clientId, exact: true }) })
    await expect(linkedRow).toContainText('Bryan PC')
    await expect(linkedRow).toContainText('Brave')
    await expect(linkedRow).toContainText('v1.0.31')
    await expect(linkedRow).toContainText('Linked')
    await expect(linkedRow).toContainText('Online')
    await expect(linkedRow).toContainText(/Last heartbeat: (Just now|\d+ seconds ago|1 minute ago)/)
    await screenshot(page, 'admin-clients-linked-default')

    await allFilter.click()
    await expect(page.getByRole('button', { name: linked.clientId, exact: true })).toBeVisible()
    await expect(page.getByRole('button', { name: unlinked.clientId, exact: true })).toBeVisible()

    await legacyFilter.click()
    await expect(page.getByRole('button', { name: linked.clientId, exact: true })).toHaveCount(0)
    const legacyRow = page.getByRole('row').filter({ has: page.getByRole('button', { name: unlinked.clientId, exact: true }) })
    await expect(legacyRow).toContainText('Legacy / Unlinked')
    await expect(legacyRow).toContainText('Offline')
    await expect(legacyRow).toContainText('Last heartbeat: No heartbeat')

    await linkedFilter.click()
    const refreshed = apiResponse(page, 'GET', '/api/admin/clients')
    await page.getByRole('button', { name: 'Refresh', exact: true }).click()
    const refreshedClients = await responseJson(refreshed)
    assert.equal(refreshedClients.filter((client) => client.clientId === linked.clientId).length, 1)

    await page.reload()
    await page.getByLabel('Admin Only Access Key').fill('isolated-browser-audit-admin')
    await page.getByRole('button', { name: 'Sign in', exact: true }).click()
    await expect(page.getByRole('button', { name: linked.clientId, exact: true })).toBeVisible()

    await page.setViewportSize({ width: 390, height: 844 })
    const phoneTable = page.getByRole('table').filter({ has: page.getByRole('columnheader', { name: 'Client ID', exact: true }) })
    const scrollContainer = phoneTable.locator('..')
    const scrollMetrics = await scrollContainer.evaluate((element) => ({
      clientWidth: element.clientWidth,
      scrollWidth: element.scrollWidth,
      overflowX: getComputedStyle(element).overflowX,
      pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    }))
    assert.ok(scrollMetrics.scrollWidth > scrollMetrics.clientWidth)
    assert.equal(scrollMetrics.overflowX, 'auto')
    assert.ok(scrollMetrics.pageOverflow <= 1, `Admin clients page overflows by ${scrollMetrics.pageOverflow}px`)

    evidence.linkedClient = {
      clientId: linked.clientId,
      deviceName: linkedRecord.deviceName,
      browserName: linkedRecord.browserName,
      extensionVersion: linkedRecord.extensionVersion,
      heartbeat: linkedRecord.extensionLastSeenAt,
    }
    evidence.unlinkedClientId = unlinked.clientId
    evidence.duplicateLinkedRecordsAfterRefresh = refreshedClients.filter((client) => client.clientId === linked.clientId).length
    evidence.phoneTable = scrollMetrics
    await page.screenshot({ path: path.join(artifacts, 'admin-clients-phone.png'), fullPage: true })
  })

  test('admin publishes version-aware extension announcements shown in the public navbar', async ({ page, evidence }) => {
    await open(page, 'admin')
    await page.getByLabel('Admin Only Access Key').fill('isolated-browser-audit-admin')
    await page.getByRole('button', { name: 'Sign in', exact: true }).click()
    await page.getByRole('tab', { name: 'Announcements', exact: true }).click()

    await page.getByLabel('Title').fill('Extension v1.0.35 available')
    await page.getByLabel('Message').fill('Improved Gmail monitoring and update notifications are now available.')
    await page.getByLabel('New extension version').fill('1.0.35')
    await page.getByRole('button', { name: 'Publish announcement', exact: true }).click()
    await expect(page.getByRole('status')).toContainText('Announcement published.')

    const card = page.getByRole('article').filter({ hasText: 'Extension v1.0.35 available' })
    await expect(card).toContainText('Published')
    await expect(card).toContainText('Extension v1.0.35')

    const outdatedResponse = await fetch(`${origin}/api/public/announcements?version=1.0.34`)
    assert.equal(outdatedResponse.status, 200)
    const outdated = await outdatedResponse.json()
    assert.equal(outdated.updateAvailable, true)
    assert.equal(outdated.latestVersion, '1.0.35')
    assert.equal(outdated.announcements.length, 1)
    assert.equal(outdated.announcements[0].title, 'Extension v1.0.35 available')

    const currentResponse = await fetch(`${origin}/api/public/announcements?version=1.0.35`)
    assert.equal(currentResponse.status, 200)
    const current = await currentResponse.json()
    assert.equal(current.updateAvailable, false)
    assert.deepEqual(current.announcements, [])
    await screenshot(page, 'admin-extension-announcement')

    await page.setViewportSize({ width: 1212, height: 650 })
    await open(page, 'dashboard')
    await expect(page.getByRole('heading', { name: 'System Active & Monitoring', exact: true })).toBeVisible()
    const announcementButton = page.getByRole('button', { name: 'Announcements, 1 unread', exact: true })
    await expect(announcementButton).toBeVisible()
    const desktopBeforeOpen = await page.evaluate(() => ({
      mainTop: document.querySelector('main').getBoundingClientRect().top,
      pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    }))
    const iconBeforeOpen = await announcementButton.evaluate((element) => {
      const rect = element.getBoundingClientRect()
      return { left: rect.left, right: rect.right }
    })
    const alertsBeforeOpen = await page.getByText('0 active alerts', { exact: true }).evaluate((element) => {
      const rect = element.getBoundingClientRect()
      return { left: rect.left, right: rect.right }
    })
    assert.ok(iconBeforeOpen.left >= alertsBeforeOpen.right, 'Announcement icon must be the rightmost visible navbar control.')
    await announcementButton.click()
    let publicAnnouncements = page.getByLabel('System and extension announcements')
    await expect(publicAnnouncements).toBeVisible()
    await expect(publicAnnouncements).toContainText('Latest extension version: v1.0.35')
    await expect(publicAnnouncements).toContainText('Extension v1.0.35 available')
    await expect(publicAnnouncements).toContainText('Improved Gmail monitoring and update notifications are now available.')
    const download = publicAnnouncements.getByRole('link', { name: 'Download Extension v1.0.35', exact: true })
    await expect(download).toHaveAttribute('href', '/api/public/extension/download')
    await expect(page.getByRole('button', { name: 'Announcements', exact: true })).toBeVisible()
    const desktopFlow = await page.evaluate(() => {
      const panel = document.querySelector('#public-announcements').getBoundingClientRect()
      const main = document.querySelector('main').getBoundingClientRect()
      const sidebar = document.querySelector('aside').getBoundingClientRect()
      const icon = document.querySelector('[aria-controls="public-announcements"]').getBoundingClientRect()
      return {
        viewportWidth: innerWidth,
        sidebarRight: sidebar.right,
        iconRight: icon.right,
        panelLeft: panel.left,
        panelRight: panel.right,
        mainTop: main.top,
        pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      }
    })
    assert.ok(desktopFlow.panelLeft >= desktopFlow.sidebarRight, 'Announcement panel must stay to the right of the desktop sidebar.')
    assert.ok(desktopFlow.panelRight <= desktopFlow.viewportWidth - 15, 'Announcement panel must stay inside the right viewport edge.')
    assert.ok(Math.abs(desktopFlow.panelRight - desktopFlow.iconRight) <= 1, 'Floating announcement panel must stay anchored to the rightmost icon.')
    assert.ok(Math.abs(desktopFlow.mainTop - desktopBeforeOpen.mainTop) <= 1, 'Floating announcement panel must not move the main content.')
    assert.ok(desktopFlow.pageOverflow <= 1, `Desktop announcement layout overflows by ${desktopFlow.pageOverflow}px`)
    assert.ok(desktopBeforeOpen.pageOverflow <= 1, `Desktop navbar overflows by ${desktopBeforeOpen.pageOverflow}px before opening announcements`)
    await page.screenshot({ path: path.join(artifacts, 'public-navbar-announcement-desktop.png'), fullPage: true })
    await publicAnnouncements.getByRole('button', { name: 'Close announcements', exact: true }).click()

    await page.setViewportSize({ width: 390, height: 844 })
    await page.getByRole('button', { name: 'Announcements', exact: true }).click()
    publicAnnouncements = page.getByLabel('System and extension announcements')
    await expect(publicAnnouncements).toBeVisible()
    const publicOverflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    assert.ok(publicOverflow <= 1, `Public announcement panel overflows by ${publicOverflow}px`)
    await page.screenshot({ path: path.join(artifacts, 'public-navbar-announcement-phone.png'), fullPage: true })
    await open(page, 'dashboard', true)
    await expect(page.getByRole('button', { name: 'Announcements', exact: true })).toBeVisible()
    await expect(page.getByRole('button', { name: /unread/ })).toHaveCount(0)

    await open(page, 'admin')
    await page.getByLabel('Admin Only Access Key').fill('isolated-browser-audit-admin')
    await page.getByRole('button', { name: 'Sign in', exact: true }).click()
    await page.getByRole('tab', { name: 'Announcements', exact: true }).click()
    const restoredCard = page.getByRole('article').filter({ hasText: 'Extension v1.0.35 available' })
    await restoredCard.getByRole('button', { name: 'Unpublish', exact: true }).click()
    await expect(page.getByRole('status')).toContainText('Announcement unpublished.')
    const hiddenResponse = await fetch(`${origin}/api/public/announcements?version=1.0.34`)
    assert.equal(hiddenResponse.status, 200)
    assert.deepEqual((await hiddenResponse.json()).announcements, [])

    evidence.extensionAnnouncement = {
      title: outdated.announcements[0].title,
      targetVersion: outdated.announcements[0].targetVersion,
      outdatedClientNotified: outdated.updateAvailable,
      currentClientAnnouncementCount: current.announcements.length,
      publicNavbarUnreadCount: 1,
      publicNavbarReadStatePersisted: true,
      publicNavbarOverflow: publicOverflow,
      publicNavbarDesktopFlow: desktopFlow,
    }
  })

  test('admin evaluation runs real samples, displays counts and restores saved history', async ({ page, evidence }) => {
    await open(page, 'admin')
    await page.getByLabel('Admin Only Access Key').fill('isolated-browser-audit-admin')
    await page.getByRole('button', { name: 'Sign in', exact: true }).click()
    await page.getByRole('tab', { name: 'Evaluation', exact: true }).click()
    await page.getByLabel('Detector', { exact: true }).selectOption('local')
    await page.getByLabel('Maximum samples').fill('60')
    await page.getByRole('button', { name: 'Run evaluation', exact: true }).click()
    await expect(page.getByText(/60 evaluated: 30 phishing, 30 legitimate/)).toBeVisible({ timeout: 30000 })
    await expect(page.getByRole('cell', { name: 'TP: 20', exact: true })).toBeVisible()
    await expect(page.getByRole('cell', { name: 'FN: 10', exact: true })).toBeVisible()
    await expect(page.getByText('83.33%', { exact: true })).toBeVisible()
    evidence.synthetic = { evaluated: 60, tp: 20, tn: 30, fp: 0, fn: 10 }
    await screenshot(page, 'admin-evaluation')
    await page.reload()
    await page.getByLabel('Admin Only Access Key').fill('isolated-browser-audit-admin')
    await page.getByRole('button', { name: 'Sign in', exact: true }).click()
    await page.getByRole('tab', { name: 'Evaluation', exact: true }).click()
    await page.getByRole('button', { name: /synthetic.*local.*completed/ }).first().click()
    await expect(page.getByText(/60 evaluated: 30 phishing, 30 legitimate/)).toBeVisible()
  })

  test('production OCR assets recognize text in an uploaded image', async ({ page, evidence }) => {
    await open(page, 'manual')
    await page.getByRole('button', { name: 'File', exact: true }).click()
    const png = await page.evaluate(() => {
      const canvas = document.createElement('canvas')
      canvas.width = 1000; canvas.height = 200
      const context = canvas.getContext('2d')
      context.fillStyle = 'white'; context.fillRect(0, 0, 1000, 200)
      context.fillStyle = 'black'; context.font = '48px Arial'
      context.fillText('Meeting tomorrow at noon', 35, 100)
      return canvas.toDataURL('image/png').split(',')[1]
    })
    await page.locator('input[type=file]').setInputFiles({ name: 'ocr-audit.png', mimeType: 'image/png', buffer: Buffer.from(png, 'base64') })
    await page.getByRole('checkbox', { name: /I am authorized to scan this item/ }).check()
    const request = page.waitForRequest((req) => new URL(req.url()).pathname === '/api/scan/file' && req.method() === 'POST', { timeout: 60000 })
    await page.getByRole('button', { name: 'Run Scan', exact: true }).click()
    const payload = (await request).postDataJSON()
    assert.match(payload.content, /Meeting tomorrow at noon/i)
    evidence.recognizedText = payload.content
    await expect(output(page)).toContainText('Safety score', { timeout: 30000 })
    await screenshot(page, 'ocr-file-output')
  })

  for (const { name, fn } of cases) {
    const evidence = { name, status: 'running' }
    report.cases.push(evidence)
    const contexts = []
    const pages = []
    const errors = []
    const external = []
    const slug = `${String(report.cases.length).padStart(2, '0')}-${name.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 85)}`
    async function newPage(options = {}) {
      const context = await browser.newContext({ viewport: { width: 1440, height: 1100 }, serviceWorkers: 'block', ...options })
      contexts.push(context)
      await context.tracing.start({ screenshots: true, snapshots: true, sources: false })
      await context.route('**/*', async (route) => {
        const url = new URL(route.request().url())
        if (url.origin === origin || ['data:', 'blob:'].includes(url.protocol)) return route.continue()
        external.push(`${route.request().method()} ${url.origin}${url.pathname}`)
        return route.abort('blockedbyclient')
      })
      const page = await context.newPage()
      pages.push(page)
      page.setDefaultTimeout(15000)
      page.on('pageerror', (error) => errors.push(error.message))
      return page
    }
    const started = Date.now()
    try {
      const page = await newPage()
      await fn({ page, newPage, evidence })
      assert.deepEqual(errors, [], 'Browser emitted an uncaught error.')
      assert.deepEqual(external, [], 'App attempted external browser network access; use a same-origin public build.')
      evidence.status = 'passed'
    } catch (error) {
      evidence.status = 'failed'
      evidence.error = error.stack ?? String(error)
    } finally {
      evidence.elapsedMs = Date.now() - started
      evidence.pageErrors = errors
      evidence.blockedExternalRequests = external
      for (let i = 0; i < contexts.length; i++) {
        await pages[i]?.screenshot({ path: path.join(artifacts, `${slug}-${i + 1}.png`), fullPage: true }).catch(() => {})
        await contexts[i].tracing.stop({ path: path.join(artifacts, `${slug}-${i + 1}.zip`) }).catch(() => {})
        await contexts[i].close()
      }
    }
    console.log(`${evidence.status.toUpperCase()}: ${name}${evidence.error ? `\n${evidence.error}` : ''}`)
    await writeFile(path.join(artifacts, 'results.json'), JSON.stringify(report, null, 2))
  }
  report.status = report.cases.every((item) => item.status === 'passed') ? 'passed' : 'failed'
  report.passed = report.cases.filter((item) => item.status === 'passed').length
  report.failed = report.cases.length - report.passed
  if (report.failed) process.exitCode = 1
}

try {
  await run()
} catch (error) {
  report.status = 'failed'
  report.error = error.stack ?? String(error)
  console.error(report.error)
  process.exitCode = 1
} finally {
  await browser?.close().catch(() => {})
  if (backend && backend.exitCode === null) {
    const exited = once(backend, 'exit').catch(() => {})
    backend.kill()
    await Promise.race([exited, delay(5000)])
  }
  report.finishedAt = new Date().toISOString()
  if (artifacts) {
    await writeFile(path.join(artifacts, 'backend.log'), backendLog)
    await writeFile(path.join(artifacts, 'results.json'), JSON.stringify(report, null, 2))
    console.log(`Acceptance ${report.status}: ${report.passed ?? 0} passed, ${report.failed ?? 0} failed. Evidence: ${artifacts}`)
  }
}
