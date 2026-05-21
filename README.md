# Tracking Threats Phishing Detection

A local-only React + Vite phishing detection system.

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
```

Do not use a normal Gmail account password. When SMTP is configured and the
Settings toggle is enabled, each saved scan can email a summary to saved report
emails. The Settings page can also send the current history digest on demand.

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
