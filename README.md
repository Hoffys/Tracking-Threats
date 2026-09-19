# Tracking Threats Phishing Detection

A React + Vite phishing detection system with an Express API, PostgreSQL or
SQLite storage, and an optional browser extension.

## Stack

- React
- Vite
- Tailwind CSS
- Framer Motion
- Context API
- localStorage persistence

## Run

```bash
npm install
npm run dev
```

The dev command starts both the Vite frontend and the Express API. The backend
stores data in `backend/threattrack.sqlite`.

The automatic demo monitor is disabled by default so local data does not fill up
with sample scans while you work. To run the app with generated demo traffic:

```bash
npm run dev:demo
```

## Railway deployment

The production backend serves the built React app from `dist` and the API from
`/api`. Use a separate Railway PostgreSQL service as the production scan
repository; SQLite remains the zero-configuration local development fallback.

Railway uses `railway.json` for the deploy settings:

```text
Build command: npm ci && npm run build
Start command: npm start
Health check: /api/health
```

Recommended production variables:

```dotenv
NODE_ENV=production
PUBLIC_DEPLOYMENT=true
VITE_PUBLIC_DEPLOYMENT=true
STORE_SCAN_CONTENT=false
SCAN_RETENTION_DAYS=30
AUDIT_RETENTION_DAYS=90
SMTP_ENABLED=false
ADMIN_API_TOKEN=replace-with-a-long-random-secret
DATABASE_URL=${{Postgres.DATABASE_URL}}
DATABASE_SSL=false
DATABASE_POOL_SIZE=10
FRONTEND_ORIGIN=https://your-railway-domain.up.railway.app
CORS_ORIGINS=https://your-railway-domain.up.railway.app
VITE_API_BASE_URL=
CORS_ALLOW_CHROME_EXTENSIONS=false
```

Create the PostgreSQL service in the same Railway project and reference its
private `DATABASE_URL` from the web service. If the database service has a name
other than `Postgres`, update the Railway reference accordingly. Do not expose a
public database endpoint. The health endpoint reports `"repository":"postgresql"`
after the connection is active.

When `DATABASE_URL` is absent, the backend uses SQLite. An attached Railway
volume mounted at `/data` with `DATABASE_PATH=/data/threattrack.sqlite` can be
kept temporarily as a rollback option, but it is not used while `DATABASE_URL`
is configured. Existing SQLite rows are not automatically copied to PostgreSQL.

Production scan submissions are recorded without raw payloads, move through a
queued/scanning/completed-or-failed lifecycle, and store normalized evidence for
the final verdict. See `docs/scan-repository-and-privacy.md` for the data map,
retention policy, privacy controls, and documented scanner limitations.

After Railway gives you the public domain, update `FRONTEND_ORIGIN` and
`CORS_ORIGINS` to that exact origin, then redeploy. If you use the browser
extension with the hosted backend, set `CORS_ALLOW_CHROME_EXTENSIONS=true` and
update `browser-extension/config.js` and `browser-extension/manifest.json`.

## Optional threat intelligence

The URL scanner works locally by default. DNS reputation uses the machine's DNS
resolver and does not need a key. External reputation checks can use these
environment variables before starting the backend. For persistent local setup,
copy `.env.example` to `.env` and fill in only the keys you have:

```dotenv
URLHAUS_AUTH_KEY=your_urlhaus_auth_key
PHISHTANK_APP_KEY=your_phishtank_app_key
VIRUSTOTAL_API_KEY=your_virustotal_key
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

The backend loads the repo-root `.env` file on startup. `.env` is ignored by Git
so personal API keys do not get committed.

URLhaus Community API lookups need a free abuse.ch `Auth-Key`. PhishTank URL
checks can run without an application key for a small number of lookups, but a
free app key gives a better rate limit. VirusTotal, Google Safe Browsing, and
AbuseIPDB are skipped until their keys are configured.

For PowerShell on Windows:

```powershell
$env:URLHAUS_AUTH_KEY="your_urlhaus_auth_key"
$env:PHISHTANK_APP_KEY="your_phishtank_app_key"
$env:VIRUSTOTAL_API_KEY="your_virustotal_key"
$env:GOOGLE_SAFE_BROWSING_API_KEY="your_google_safe_browsing_key"
$env:ABUSEIPDB_API_KEY="your_abuseipdb_key"
npm run dev
```

When a URLhaus key is missing or a provider rate-limits or rejects a lookup, the
Threat intelligence summary shows the provider error instead of only a generic
unavailable status.

## Email reports

Notification recipient emails are saved by the backend from the Settings page.
To send scan summaries and manual history digests through Gmail SMTP, fill these
repo-root `.env` values with a Gmail address and Gmail app password:

```dotenv
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=your_sender_gmail@gmail.com
SMTP_PASS=your_gmail_app_password
SMTP_FROM=your_sender_gmail@gmail.com
SMTP_TLS_REJECT_UNAUTHORIZED=true
```

Do not use a normal Gmail account password. When SMTP is configured and the
Settings toggle is enabled, each saved scan can email a summary to saved report
emails. The Settings page can also send the current history digest on demand.
Keep SMTP TLS certificate verification enabled. If a local antivirus, proxy, or
development network intercepts Gmail SMTP certificates and Node reports a local
certificate-chain verification error, `SMTP_TLS_REJECT_UNAUTHORIZED=false` can
be used only as a local troubleshooting override.

## Pages

- Dashboard
- Live Monitor
- Email Analyzer
- Manual Scan
- Scan History
- Alerts

## Browser link monitoring

The `browser-extension` folder contains a local Chrome/Edge extension that sends
visited HTTP/HTTPS pages to the backend URL scanner. This lets opened links show
up in the dashboard, live monitor, alerts, and scan history.

1. Start the app:

```bash
npm run dev
```

2. Open Chrome or Edge extensions:

```text
chrome://extensions
edge://extensions
```

3. Enable Developer mode, choose "Load unpacked", then select:

```text
browser-extension
```

The extension ignores `localhost` pages to avoid scanning the app itself.
Google search-result links are preview-scanned for warnings before they are
opened. A search result is not stored or added to the browser block list until
the browser actually navigates to that URL.
