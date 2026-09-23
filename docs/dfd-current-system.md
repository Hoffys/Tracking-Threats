# Tracking Threats Current System DFD

![Tracking Threats Level 0 DFD](dfd-current-system-clean.png)

[Editable SVG version](dfd-current-system.svg)

This is a Level 0 / single-process DFD of the deployed system. It replaces the
proposal's local SQLite store with a separate private Railway PostgreSQL
service. It also makes webmail consent and external data recipients explicit.

| ID | Element | Current implementation |
| --- | --- | --- |
| - | Client | Submits manual URL, email, message, and file scans; views results; manages settings and deletion. |
| - | Browser extension | Scans navigated URLs, search links, download metadata, and consented visible webmail content. |
| - | Websites, search engines, webmail | Browser-visible sources observed by the extension. Gmail content is not read for scanning before consent. |
| - | Reputation providers | Configured VirusTotal, Google Safe Browsing, URLhaus, PhishTank, AbuseIPDB, and DNS checks. |
| - | Email provider | SMTP or Resend delivers optional scan summaries and history digests. |
| 0 | Tracking Threats system | Validates, analyzes, scores, explains, redacts, stores, and deletes scan records. |
| D1 | Scan repository | Separate private Railway PostgreSQL service; not a GitHub repository. |
| D2 | Extension local storage | Stores the browser's webmail consent decision, notice version, timestamp, and client identifier. |

## Flow sequence

1. The client sends a manual scan request, privacy acknowledgment, settings change, or
   deletion request to process 0. Process 0 returns the result, history,
   dashboard information, or confirmation.
2. The client accepts or declines the confidentiality notice in the browser
   extension. The extension stores and
   checks that decision in D2 before reading email content for scanning.
3. Website, search, and webmail sources supply browser-visible URLs, search
   results, download information, and (only after consent) visible webmail
   content to the extension.
4. The extension sends scan input to process 0. Email requests contain sender, subject,
   body, links, and the consent acknowledgment; process 0 returns a verdict
   or block decision to the extension.
5. Process 0 sends relevant URL, hostname, IP, or SHA-256 lookups to reputation providers and
   receives reputation results or provider errors.
6. Process 0 writes redacted submissions, results, evidence, consent records,
   and settings to D1. It reads records from D1 for history, monitoring,
   reports, and deletion.
7. When enabled, process 0 sends a report summary or digest to the email provider; it
   delivers it to the saved recipient and returns a delivery result.

## Important boundaries

- Email scanning requires an explicit opt-in in the extension. Declining leaves
  email content monitoring off, but general URL monitoring may continue.
- The extension analyzes only visible Gmail inbox previews (up to 50 per pass)
  and opened messages, not the whole mailbox in one operation. Other supported
  webmail clients use opened-message checks.
- Email sender, subject, body, and links travel to the backend for analysis
  after consent. Production with `STORE_SCAN_CONTENT=false` does not retain raw
  email bodies or the original uploaded file in PostgreSQL.
- Redacted scan submissions, results, evidence, consent records, notification
  settings, and operational records are stored in D1. D2 is not the scan
  repository.
- Depending on provider configuration, URL, hostname, IP address, or file hash
  may be disclosed for reputation checks. Optional reports go to saved email
  recipients via the email provider.
- Scan records expire after 30 days by default. The old Railway SQLite volume
  is only a temporary rollback source and may still contain historical data.
