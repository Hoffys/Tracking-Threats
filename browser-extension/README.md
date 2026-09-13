# Tracking Threats Browser Extension

Before loading or packaging the extension for a hosted deployment:

1. Edit `config.js`.
   - `API_BASE_URL` should be your hosted backend origin, for example `https://tracking-threats-api.example.com`.
   - `APP_URL` should be your hosted frontend origin, for example `https://tracking-threats.example.com/`.

2. Edit `manifest.json`.
   - Replace `https://your-backend-domain.com/*` with your real hosted backend origin plus `/*`.
   - Keep `http://localhost:4000/*` only if you still test the extension locally.

3. Configure backend CORS.
   - If using the unpacked browser extension with hosted backend, set `CORS_ALLOW_CHROME_EXTENSIONS=true`.
   - Keep public deployment privacy settings enabled:
     `PUBLIC_DEPLOYMENT=true`, `STORE_SCAN_CONTENT=false`, and `SMTP_ENABLED=false`.

The extension scans visited HTTP/HTTPS pages, supported search results, and supported webmail pages. It also includes a lightweight static ad and malvertising ruleset in `rules/adblock-rules.json` to block common ad delivery, popup, and tracking domains before they load. Do not publish it without clear user consent and privacy wording.
