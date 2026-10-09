# Scan Repository, Methodology, and Privacy Design

Version: 2026.10

## Purpose

Tracking Threats accepts user-authorized URLs, email text, SMS text, and files
for automated phishing and malware-indicator analysis. The repository provides
an auditable record of the request, result, and supporting evidence without
making an authenticity guarantee.

## Processing flow

1. Validate the request and privacy acknowledgment.
2. Create a `scan_submissions` row with status `queued`.
3. Change the submission status to `scanning`.
4. Analyze the item with local rules and configured reputation providers.
5. Calculate the rule-based 0-100 score and response policy; report check coverage separately.
6. Store the scan result, normalized evidence, methodology version, and expiry.
7. Mark the submission `completed`, or `failed` with a limited error message.
8. Delete expired records during scheduled retention cleanup.

## Repository tables

Production uses a dedicated PostgreSQL service connected to the application
over Railway's private network. Local development uses SQLite when
`DATABASE_URL` is not set. The database is a data repository, not a GitHub code
repository, and it must not have a public endpoint.

| Table | Purpose | Raw content in public production |
| --- | --- | --- |
| `scan_submissions` | Intake queue and processing lifecycle | No |
| `scans` | Final score, verdict, redacted target, and result metadata | No |
| `scan_evidence` | Local-rule and provider findings behind the verdict | No |
| `email_scans` | Email-specific result fields | No |
| `message_scans` | Message-specific result fields | No |
| `blocked_threats` | Block/review workflow | No |
| `privacy_consents` | Notice version, acknowledgment, and processing basis | No |
| `system_logs` | Operational and security events | No raw payloads |
| `notification_settings` | User-selected report recipients and preferences | Email address only |
| `client_credentials` | Client ID and SHA-256 hash of its access token | No token plaintext |
| `admin_actions` | Admin deletion audit with hashed client reference | No raw scan content |

## Data minimization

Public production must use:

```dotenv
PUBLIC_DEPLOYMENT=true
VITE_PUBLIC_DEPLOYMENT=true
STORE_SCAN_CONTENT=false
```

With this setting, the repository redacts full URLs, email local parts,
extracted links, message targets, and file names. It does not retain email
bodies, SMS bodies, or extracted file text. File size, MIME metadata, extension,
SHA-256, verdict, and evidence may be retained.

The browser reads at most the first 200 KB of a selected file as text for static
indicators. SHA-256 is calculated from the complete selected file. The original
file is not uploaded as a binary object or retained by the backend.

## Browser email consent

Webmail monitoring is disabled until the user accepts confidentiality notice
version `2026.09` inside the browser extension. The notice identifies the
visible sender, subject, message text, links, and visible Gmail inbox previews
that may be sent to the backend for analysis. Declining leaves monitoring off.
The user can withdraw consent from the webmail monitor, which stops future
email scans and removes injected scan labels from the page.

The extension stores the consent decision, notice version, decision timestamp,
and a separate private client credential in browser-local extension storage.
The backend rejects public
`browser-email-monitor` requests that do not include the acknowledgment.

## Retention and deletion

Default production values:

```dotenv
SCAN_RETENTION_DAYS=30
AUDIT_RETENTION_DAYS=90
```

- Scan results and related evidence expire after 30 days.
- Failed intake records and system logs expire after 90 days.
- Admin deletion audit records expire after 90 days.
- Cleanup runs at startup and every six hours.
- Public Clear History permanently deletes rows associated with the
  authenticated browser client.
- Delete My Data also deletes saved report-email settings and revokes the
  browser client credential.
- Admin deletion requires an admin token, a manual request-verification
  acknowledgment, and exact client ID confirmation. It leaves a limited audit
  record without the raw client ID.
- Inactive client credential rows expire automatically after 180 days by default; they are also revoked by
  Delete My Data or admin deletion. A formal inactivity-retention rule is still
  needed before wider public use.

## External processors and data recipients

Configured checks may disclose only the data required for the check:

- VirusTotal: URL or SHA-256
- Google Safe Browsing: URL
- URLhaus: URL or hostname
- PhishTank: URL
- AbuseIPDB: resolved public IP address
- DNS resolver: hostname
- Railway: application hosting and encrypted transport endpoint
- Configured email provider: report recipient and generated scan summary

The deployed privacy notice must disclose that infrastructure and provider
processing may occur outside the Philippines.

## Security controls

- HTTPS and Helmet security headers
- Restricted CORS origins and API rate limits
- Random pseudonymous client IDs with per-browser access tokens; only token
  hashes are stored server-side
- Separate admin token for administrative APIs, held only in page memory
- Secrets kept in Railway variables and excluded from Git
- No-store API cache policy
- Separate private Railway PostgreSQL service for production scan records
- Normalized evidence and redacted operational logs
- Data-subject deletion controls

The client ID alone does not authorize access to public history, notification
settings, or deletion. Existing pre-credential records remain in the
repository until retention cleanup or verified admin deletion, but cannot be
claimed merely by knowing their client ID. This is an anonymous browser-based
credential model, not a named-user account system. Formal multi-user use
would still need individual accounts, stronger administrator authentication,
and a documented identity-verification procedure for manual deletion.

## Verdict interpretation and coverage

The score is rule-based, not a calibrated probability of safety or phishing.
Raw compatibility statuses remain unchanged:

- Safe (80-100): display **No strong indicators** when coverage is complete,
  otherwise **Incomplete checks**.
- Suspicious (51-79): display **Caution** and request review.
- Dangerous (0-50): display **Risk detected**. This does not confirm phishing.

A manual result or search preview does not itself block access. A stored block
policy and an actual browser enforcement action are distinct. Local allowlist
and manual safe-host exceptions bypass reputation checks and report local-only
coverage; an exception does not establish safety.

Results include top-level `coverage` with `status` (`complete`, `partial`,
`unavailable`, or `local-only`), `checkedProviders`, `totalProviders`, optional
`linksChecked`/`totalLinks`, and a `limitations` array. Missing provider keys,
skipped checks, and lookup errors are not clean results. A provider can display
?No match? only after a completed check; a database miss is not an authenticity
guarantee. Historical results without coverage are displayed conservatively.

Top-level `categories` may contain `phishing-indicators`, `malware-reputation`,
`ip-reputation`, `gambling-content`, `piracy-content`, and `file-risk`.
`categoryWarnings` is an optional array of content-warning strings. Gambling
and piracy warnings appear separately from phishing indicators; they do not
establish phishing. The UI preserves these fields in browser-local public
history and extension search-preview fragments. Preview fragments are display
snapshots, not saved or authenticated scan records.

URL inspection uses local URL features, reputation providers, up to three HTTPS
redirects, and at most 512 KB of static HTML from public network addresses. The
extension can submit bounded rendered-form signals after the user clicks
"Inspect this page." These checks do not execute a destination in an isolated
sandbox or establish who owns it. Email and SMS reputation checks cover at most
five unique links, with two checks in flight; extra links remain unchecked and
are reflected in coverage. Messages without links have local-only coverage.
File scans also report coverage. Complete coverage only describes the selected
checks, not exhaustive detection.

Image files up to 8 MB can be processed locally in the user's browser for English
OCR and QR/barcode values before extracted text is submitted for scanning. Files
are not uploaded to a sandbox or executed by Tracking Threats. When a supplied
hash already has VirusTotal verdicts, a MalwareBazaar listing, or a MetaDefender
multi-engine result, that remote
reputation evidence is used.
Unknown files are not submitted for detonation. Document signature validation,
issuing-organization verification, and full binary forensics are not provided.
Important IDs, contracts, certificates, invoices, and payment requests must be
verified with the issuer. Reputation data can be delayed, incomplete, or wrong.

## Data Privacy Act alignment

The design supports transparency, legitimate purpose, proportionality, data
minimization, retention, security, and data-subject deletion. The project team
must still complete a Privacy Impact Assessment, assign a responsible privacy
contact, review processor terms, document incident response, and obtain school
or legal review before treating this document as a complete compliance finding.
