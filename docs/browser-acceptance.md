# Isolated browser acceptance

The standalone runner is `tests/e2e/run-browser-acceptance.mjs`. It uses real Playwright UI interactions against the existing production `dist` served by a newly started local backend. It never targets Railway or an existing backend. Read the Browser skill before choosing this fallback; this session has no callable Browser/NodeREPL tools and standalone Playwright was explicitly authorized.

## Prerequisites and coordination

Do not start the UI run until main confirms the frontend build is ready. Main must build with `VITE_PUBLIC_DEPLOYMENT=true` and an empty `VITE_API_BASE_URL` (same-origin requests). The harness does not build, modify package manifests, deploy, or commit. Rebuilds must not run concurrently with acceptance.

Install Playwright outside the repository, using Windows system certificates and the already installed browser:

```powershell
$e2eTools = Join-Path $env:TEMP ('tracking-threats-e2e-tools-' + [guid]::NewGuid().ToString('N'))
$env:NODE_OPTIONS = '--use-system-ca'
$env:PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD = '1'
npm.cmd install --prefix $e2eTools --no-audit --no-fund --save-exact @playwright/test
$env:E2E_PLAYWRIGHT_NODE_MODULES = Join-Path $e2eTools 'node_modules'
$env:E2E_BROWSER_EXECUTABLE = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
node tests/e2e/run-browser-acceptance.mjs --check
```

`E2E_PLAYWRIGHT_NODE_MODULES` is the absolute **node_modules directory**, not the package directory. `E2E_BROWSER_EXECUTABLE` is an absolute existing Chromium-family executable. No root dependency installation is needed. Missing prerequisites exit nonzero with a specific error; `--check` validates availability only and explicitly reports that acceptance did not run.

Only after the build-ready signal:

```powershell
node tests/e2e/run-browser-acceptance.mjs --build-ready
```

The runner exits nonzero on any assertion, unexpected external browser request, page exception, or infrastructure failure. It cannot silently skip unavailable browser checks. Optional `E2E_HEADED=true` shows the isolated test browser; the default is headless. Never supply an existing user profile or connect to a running browser.

## Isolation

Every execution creates a unique TEMP directory for SQLite, logs, screenshots, Playwright traces, and `results.json`. The backend starts with that directory as its working directory, preventing the root `.env` from being loaded. Only OS runtime environment variables are inherited. Explicit overrides include:

```text
NODE_ENV=production
DATABASE_URL=
DATABASE_PATH=<new TEMP directory>/acceptance.sqlite
PUBLIC_DEPLOYMENT=true
STORE_SCAN_CONTENT=false
AUTO_MONITOR=false
SMTP_ENABLED=false
RESEND_API_KEY=
REPUTATION_ENABLED=false
URLHAUS_AUTH_KEY=
VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
PHISHTANK_APP_KEY=
ABUSEIPDB_API_KEY=
```

SMTP host/user/password/from and Resend sender are also cleared. A free local port is selected; the runner checks `/api/health` for SQLite. Each scenario receives a new browser context with no existing cookies or storage. Browser requests to other origins are blocked and reported as failures. Only fictional SMS, reserved example URLs, and `acceptance@example.invalid` are used. Provider enrichment is disabled, and no digest is sent. Browser and backend are stopped after the run; TEMP evidence is retained for review.

## Acceptance checks

| Check | Real UI behavior/assertions |
| --- | --- |
| Benign SMS | Consent gate; real scan response; benign score; local-only limits; same scan ID, score and summary in history after reload. |
| Direct credential SMS | Fictional password/OTP request is flagged; manual result does not claim automatic access blocking; history survives reload. |
| Offline URL | Scan `https://example.com/` without visiting it; zero checked providers; explicit incomplete/unavailable coverage; no plain Safe badge; limitations survive history reload. |
| Settings and data deletion | Save a reserved email and disabled preferences, reload, verify persistence and disabled digest; Delete My Data; reload and verify email/history removal. |
| Own history deletion | Two independent browser clients create records via UI; delete first client's history; reload proves removal while second client's record survives. |
| Preview roundtrip | Partial, unavailable, local-only, and missing legacy coverage; extension serializer to app parser deep equality; exact displayed target, score, summary, warnings, recommendations, categories and limits; reload remains exact; no scan POST or saved history entry. |
| Invalid preview | Malformed fragment displays explicit invalid-preview message without creating history. |

Preview fixtures are deliberately synthetic display snapshots, not live reputation findings. The runner executes the extension's actual preview serializer in a Node sandbox and navigates its generated local URL in the real browser. It does **not** claim installed-extension, search-engine badge, or navigation-block enforcement coverage. It does not stub the app API or replace backend scan results. All scan/settings/delete actions run through the UI; observing their HTTP responses supplies IDs and evidence. Direct health polling only starts the temporary service.

## Evidence and current status

Executed on 2026-09-30 after main confirmed public build `index-WnibWWX4.js` ready: **10 passed, 0 failed**, exit code 0. The latest run used Edge 154.0.4258.37 and Playwright 1.63.0, from 05:42:46 to 05:43:08 UTC (13:42:46 to 13:43:08 Asia/Taipei). The preceding run at 05:40:57–05:41:18 UTC also passed 10/10. Dist index SHA-256: `cba70c4489ce112139d38f995831c6767ab0a5099a79a1fbcf8cd4f98ffb7916`.

Actual observations:

- Benign conversational SMS scored 100/100; direct password/OTP request scored 33/100 and displayed risk/review wording with an explicit manual-scan non-blocking disclaimer.
- Offline `https://example.com/` scored 100/100 locally but showed **Incomplete checks**, **Checks unavailable: 0/1 providers checked**, a skipped provider, and a statement that this is not a verified safe result.
- Scan IDs/scores/history persisted through reload; notification email and both disabled preferences persisted. Delete My Data removed the current client's email/history; Delete Scan History survived reload and preserved the second client's record.
- Partial, unavailable, local-only and legacy previews preserved their exact display data through extension serialization, app parsing and browser reload. Each produced zero scan POSTs and no saved record. Malformed preview showed an explicit error.
- Zero uncaught page errors and zero external browser requests were recorded. The backend log confirmed SQLite and disabled auto-monitoring. Its local listening port was gone after completion.
- Manual credential result, offline URL result and partial-preview screenshots were visually reviewed. Installed-extension operation and live provider behavior remain outside this run's coverage.

The first run had 9 passes and one harness false positive: an overly broad text assertion matched the negated disclaimer “does not ... prove that access was blocked.” The assertion now matches affirmative claims and explicitly requires the manual-scan disclaimer for blocked-policy results. No application fix was required; the complete rerun passed.

Latest full successful evidence: `C:\Users\Bry\AppData\Local\Temp\tracking-threats-browser-acceptance-DoEEnS` (`results.json`, `backend.log`, screenshots and traces). The preceding successful evidence is retained in `C:\Users\Bry\AppData\Local\Temp\tracking-threats-browser-acceptance-DfI2Ru`; initial harness failure evidence remains in `C:\Users\Bry\AppData\Local\Temp\tracking-threats-browser-acceptance-iFnd4Q`. A compact durable record of the latest run is saved at `tests/e2e/results/2026-09-30-browser-acceptance.json` (no commit was made).

Screenshot QA at the tested 1440×1100 viewport: the credential result clearly displayed risk/review wording and its manual-scan disclaimer; the offline URL used amber incomplete/unavailable labels with 0/1 providers checked; the partial preview displayed the exact target and fixture text, provider/link counts, separate content warnings and empty saved history. No clipped primary content or overlapping form controls was observed. The credential result's notification toast temporarily overlaid the lower recommendations area; the main result and disclaimer remained readable. The runner now also includes a 390×844 responsive-navigation and horizontal-overflow case; it needs a fresh browser run before that new case is recorded as passing.

Acceptance is complete for the recorded build. Main's subsequent Methodology table rebuild and remaining backend unit regressions are separate; this report does not claim to validate changes made after the backend process started. Per main's instruction, no further browser reruns are required for the remaining formatting/email-link changes.

Syntax and prerequisite validation also passed. Missing dependency configuration and a missing `--build-ready` gate were exercised and both returned exit code 1 without starting a browser/backend. The successful `--check` explicitly reported `browserLaunched=false`, `backendStarted=false`, and `acceptanceRun=false`.

The current session's external modules are at `C:\Users\Bry\AppData\Local\Temp\tracking-threats-e2e-tools-81ecfc5118d3446bb411d1e1d70f9bf7\node_modules`. Set `E2E_PLAYWRIGHT_NODE_MODULES` to this path to reuse the preparation installation; recreate it with the commands above if TEMP is cleared.

Each actual run prints its TEMP artifact directory. `results.json` records browser/Playwright versions, dist index SHA-256, case outcomes, errors, blocked external requests and relevant scan response/snapshot evidence. Each case retains screenshots and traces, including failures, plus `backend.log`. Review the screenshots and report failures to main for application fixes; only harness changes belong in `tests/e2e/` and this document.

To open a retained trace using the external installation:

```powershell
node (Join-Path $env:E2E_PLAYWRIGHT_NODE_MODULES 'playwright/cli.js') show-trace '<TEMP artifact directory>\<case>.zip'
```

## Verdict wording update, 2026-09-30

The later public build `index-C0C-UxUd.js` passed all 10 browser cases. A completed low-indicator scan now displays **Appears safe**, with separate check limitations and an explicit **Scan finished; no further checks are pending** message. Caution and risk verdicts retain their severity. Failed scans remain unavailable and are not presented as successful safe assessments. The actual offline-result screenshot was reviewed: the green verdict, completed-scan wording, and unavailable-provider details are visible and readable. Evidence: `tests/e2e/results/2026-09-30-verdict-labels.json`. Earlier results above describe the previous wording.
