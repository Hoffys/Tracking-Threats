# Tracking Threats Browser Extension

Users can now open **Get Extension** on the hosted website to download the manual
installation ZIP and follow the setup instructions. Version 1.0.26 reports its
client ID, version, and latest activity every five minutes using browser alarms.
Update existing unpacked extensions and reload them to enable this reporting.
The Admin usage section separates ZIP download requests from extension clients
and recently active system clients. These are not unique-person counts.

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

Version 1.0.23 scans visible Gmail inbox rows in batches of at most 50 attempts,
with at most four requests in flight. After each batch, it pauses and shows the
sender, subject, and outcome for each attempted row. "Not now" leaves inbox
scanning paused; "Scan next 50" authorizes another batch. If no unscanned rows
are visible, open the next Gmail page manually. The review list stays only in
the current Gmail tab's memory and disappears when that tab is reloaded or
email scanning is turned off. Opened-email scanning remains enabled while inbox
scanning is paused; use "Turn off" to withdraw consent for all email scanning.
Reload the unpacked extension and then reload Gmail to use the new content script.

Version 1.0.24 also ends a batch when no more eligible messages are visible,
even if fewer than 50 were checked. For example, 45 eligible rows on a Gmail
page now trigger the review and next-batch choice. Each new choice still allows
at most 50 additional attempts.

Version 1.0.25 automatically registers a fresh client ID and token when a scan
is rejected after client deletion, then retries the scan once. Concurrent scans
share the replacement identity. Deleted history stays deleted. The linked web
app also checks its credentials and adopts the extension's new ID. Deploy the
updated backend and frontend, reload the unpacked extension, then refresh the
app tab to load the updated credential bridge.
