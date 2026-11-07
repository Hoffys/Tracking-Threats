# Tracking Threats Browser Extension

Version 1.0.46 adds an explicit Outlook Cloud Scan Folder flow using the shared batch engine. It inspects Inbox and Sent Items conversations one at a time, submits only individually identified visible message content, and labels conversations incomplete because collapsed or unloaded messages cannot be verified. The user must manually scroll the virtual list to reveal more conversations. Gmail batching remains unchanged. Email consent is updated to 2026.12; users must accept it before email scanning resumes. Outlook Cloud is added as a supported content-script host; no optional Chrome permissions or broad host patterns are added.

Version 1.0.43 adds an explicit privacy choice for Google Search Results Monitoring: users can save scan records, use non-persistent previews, or turn search scanning off. Persisted requests carry the accepted 2026.10 privacy notice version. Version 1.0.42 starts URL scans at navigation intent, deduplicates concurrent navigation scans, reuses recent verdicts without fragment-only duplicates, and avoids applying a late verdict to a tab that has moved to another URL. Backend navigation scans time out after 12 seconds and fail open with a warning in extension status. Startup reconciles persistent dynamic rules with remembered blocked hosts. The blocked page displays the current original URL and scan coverage details. MV3 still cannot pause the first request to an unknown URL until the backend verdict returns. No new runtime permissions were added.

The extension uses `activeTab` for user-requested rendered-page inspection instead
of permanent access to every website. URL navigation and download monitoring remain
in the background; opening the popup and choosing **Inspect this page** temporarily
allows form and rendered-page signals to be read from the active tab.

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
   - Release packages must include only the hosted API origin; do not include localhost host permissions.

3. Configure backend CORS.
   - If using the unpacked browser extension with hosted backend, set `CORS_ALLOW_CHROME_EXTENSIONS=true`.
   - Keep public deployment privacy settings enabled:
     `PUBLIC_DEPLOYMENT=true`, `STORE_SCAN_CONTENT=false`, and `SMTP_ENABLED=false`.

The extension scans visited HTTP/HTTPS pages, supported search results, supported webmail pages, and new browser downloads. Google Search Results Monitoring stays off until the user chooses saved monitoring, preview-only monitoring, or off. Saved monitoring sends eligible destination URLs to the backend and records scans in Scan History; preview-only uses the non-persistent preview path. Search-page query text and unrelated page content are not collected by this feature. Users can review or change the preference from the search monitor. Email scanning requires separate consent. Dangerous downloads are canceled when the source URL or file indicators are marked high risk. It also includes a lightweight static ad and malvertising ruleset in `rules/adblock-rules.json` to block common ad delivery, popup, and tracking domains before they load.

Email monitoring is declared for Gmail, Outlook, Yahoo Mail, Proton Mail, iCloud Mail, Zoho Mail, AOL Mail, and Mail.com. For opened messages, provider adapters submit the visible sender, subject, body text, and visible links to `POST /api/scan/email`; recipient details and raw RFC 822 messages are not collected. Gmail batch scanning processes rendered previews only in the currently selected Gmail mail view. Outlook Cloud has an explicit Scan Folder action for supported Inbox and Sent Items routes; it opens conversations sequentially in the visible interface, extracts only messages with validated individual-message identifiers and complete visible content, and marks each inspected conversation incomplete because collapsed or unloaded messages cannot be verified. It does not switch folders or automatically scroll; the user can reveal additional virtualized rows by scrolling. Batch sizes are 10–50 and the shared engine caps in-flight requests at four. Other providers do not use batch scanning. DOM selector fixtures do not guarantee compatibility with live authenticated sites. Consent is shared across supported webmail in the browser and can be withdrawn with the in-page Turn off control. Withdrawal prevents new scans and ignores results for a message that is no longer open, though a request already sent may finish.

The backend's `STORE_SCAN_CONTENT` setting controls retention of submitted scan content. `STORE_SCAN_CONTENT=true` retains it. In a public deployment, content is not retained by default unless that setting is explicitly true; in non-public deployments, content is retained by default unless set to false. This repository does not establish the current Railway value. Deployments should set and verify the value they intend to use and keep the published Privacy Notice consistent with that configuration.

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

Version 1.0.30 replaces persistent `<all_urls>` host access with `activeTab` and
`scripting`. Open the popup and choose **Inspect this page** to authorize a
one-time rendered-form check for the active page. The extension sends bounded
counts and booleans, not page HTML. Navigation URL monitoring, reputation
checks, and dynamic block rules continue to run with their declared browser
permissions. Reload the unpacked extension after installing this version.

Version 1.0.31 separates phishing results from piracy-related download risk.
A result with no strong phishing indicators now shows **Download risk unknown**
when piracy content is detected, along with malware, fake-mirror, tampered-file,
and copyright-risk guidance. The phishing score is unchanged because piracy
content alone is not proof of phishing.

Version 1.0.32 expands the piracy warning to named torrent, repack, cracked-
software, and mirror indicators instead of treating FitGirl as a special case.
All separate content-risk categories now use an amber content warning rather
than the ordinary green safe presentation.

Version 1.0.33 adds live popup/badge updates, SPA navigation monitoring, alarm-based safe-host refresh, and pauses downloads while checks run. URL rules now use DNR block actions, which work without broad host grants; the tab API opens warning pages separately. Cancellation failures are reported as risk, not successful blocking. No permissions were added. See `docs/audit-2026-10-01.md` in the project for verification and limitations.

Version 1.0.41 blocks navigation and cancels downloads when a scan matches the `piracy-content` policy. Search badges remain **CAUTION - PIRACY RISK**, and the blocked page explicitly describes a content/download-risk policy decision instead of claiming that malware was confirmed. Version 1.0.40 introduced the matching caution label and retained the explanation that URL checks do not rate the actual downloadable file. Version 1.0.39 keeps the Gmail batch-size control visible in the monitor while retaining selectable batches of 10, 20, 30, 40, or 50 messages. The selected size is remembered. Version 1.0.37 added expandable scan details to Gmail and Google result prompts while retaining their links to Tracking Threats History. Version 1.0.35 added a version-aware announcement panel in the extension popup. Staff can publish extension updates, security advisories, maintenance notices, and general announcements from the Admin page. Update cards compare the installed manifest version with the published target version and link only to the official extension download endpoint. Read announcements are remembered in local extension storage. No permissions were added.

Version 1.0.34 reconnects blocked results to this browser's saved History before enabling the details link. Missing/expired/deleted records are rescanned using the real detector, and persistent block-rule visits now save fresh automatic activity. Connection failures show a retry control instead of an empty history link. No permissions were added. Replace the unpacked extension files and reload the extension to activate this update; refreshing the website alone does not update extension code.
