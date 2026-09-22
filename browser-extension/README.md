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

The extension scans visited HTTP/HTTPS pages, supported search results, supported webmail pages, and new browser downloads. Dangerous downloads are canceled when the source URL or file indicators are marked high risk. It also includes a lightweight static ad and malvertising ruleset in `rules/adblock-rules.json` to block common ad delivery, popup, and tracking domains before they load. Do not publish it without clear user consent and privacy wording.

Version 1.0.22 registers a new protected client identity. Reload the unpacked
extension after updating the backend. Older extension versions cannot save new
scan history after the client access change. Opening History from the extension
passes only the client ID in the link. A content script on the Tracking Threats
origin transfers the credential to the app after navigation. Do not add the
credential to links placed in Gmail, search results, or other third-party pages.
