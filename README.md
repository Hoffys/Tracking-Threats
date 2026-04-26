# Tracking Threats Phishing Detection

A local-only React + Vite phishing detection system prototype.

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
