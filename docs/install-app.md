# Install Tracking Threats

1. Open https://tracking-threats-production.up.railway.app/ in desktop Chrome or Edge.
2. Click **Install App** at the top of the page and accept the browser prompt.
   If the browser has not offered a prompt, the button displays installation instructions.
3. Open **Tracking Threats** from the Windows Start menu or the shortcut created by your browser.
4. Use Scan, History, Learn, and Settings in the app window. Internet access is required for server features.

## Browser extension

Install the extension separately in the same desktop browser profile. For the current
unpacked development version, open `chrome://extensions` (or `edge://extensions`),
enable Developer mode, choose **Load unpacked**, and select the project's
`browser-extension` folder. Keep that folder on disk. If already installed, click
**Reload** instead. The extension is configured to connect to the Railway backend.

Browse supported search pages normally. Open History from the extension to view
its linked client history. A standalone app launched without the extension's client
link may show its own web client history instead. Email scanning requires consent.
PWA installation neither installs the extension nor signs in to a Google account.

## Offline and updates

The service worker caches only a static offline message. API responses, credentials,
scan results, and application bundles are not cached by it. Reconnect and reopen
the app to load the current website version. The unpacked extension still requires
a manual reload after its files change.

## Verification

In Chrome DevTools, open **Application → Manifest** to inspect the app's identity and
192/512 pixel icons. Under **Service Workers**, verify `/sw.js` is registered after
a production page load. Test offline navigation and reconnect before testing scans.
