# Tracking Threats browser extension

Open https://tracking-threats-production.up.railway.app/ in desktop Chrome or
Edge. Click **Get Extension**, then **Download Extension ZIP**. Extract the ZIP
to a permanent folder and follow the on-screen setup steps. Select the
`tracking-threats-extension` folder containing `manifest.json` when choosing
**Load unpacked** in the browser's extensions page.

For an existing installation, replace the files in its folder and click
**Reload** on the extensions page. The extension connects to the Railway
backend automatically. Browse supported pages normally, then open the extension
popup to check scan status and linked history. Email scanning requires consent.

## Admin usage monitoring

Sign in to Admin to see ZIP download requests, registered extension clients,
active extensions (24 hours / 7 days), and active system clients (24 hours /
7 days). Use Refresh for current counts or Download CSV in Reports. Download
requests include repeats and do not prove installation. Active clients are
credentialed browser clients recently contacting the server, not verified
unique people or currently online users. Extension-specific metrics require
version 1.0.26 or newer. The dashboard displays when tracking began; prior
downloads cannot be reconstructed. Deleting a client's data removes its usage
timestamps and client counts. The anonymous download counter remains.

## Local development

Open `chrome://extensions` or `edge://extensions`, enable Developer mode,
choose **Load unpacked**, and select the project's `browser-extension` folder.
Keep that folder on disk. If already installed, click **Reload** instead.
