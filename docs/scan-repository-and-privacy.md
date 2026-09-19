# Scan Repository, Methodology, and Privacy Design

Version: 2026.09

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
5. Calculate the 0-100 safety score and response policy.
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

The extension stores only the consent decision, notice version, and decision
timestamp in browser-local extension storage. The backend rejects public
`browser-email-monitor` requests that do not include the acknowledgment.

## Retention and deletion

Default production values:

```dotenv
SCAN_RETENTION_DAYS=30
AUDIT_RETENTION_DAYS=90
```

- Scan results and related evidence expire after 30 days.
- Failed intake records and system logs expire after 90 days.
- Cleanup runs at startup and every six hours.
- Public Clear History permanently deletes rows associated with the current
  pseudonymous client ID.
- Delete My Data also deletes saved report-email settings.

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
- Random pseudonymous client IDs
- Separate admin token for administrative APIs
- Secrets kept in Railway variables and excluded from Git
- No-store API cache policy
- Separate private Railway PostgreSQL service for production scan records
- Normalized evidence and redacted operational logs
- Data-subject deletion controls

The client ID currently acts as a bearer identifier for public history. It must
not be published or shared. Account authentication and a server-issued session
credential are recommended before supporting higher-risk or multi-user data.

## Verdict interpretation

- Safe (80-100): no configured strong threat indicator was detected.
- Caution (51-79): one or more indicators require human review.
- Dangerous (0-50): high-risk indicators triggered the block policy.

Safe does not mean authentic. The scanner does not currently execute files in a
sandbox, validate document signatures, verify issuing organizations, perform
OCR, or conduct full binary forensics. Important IDs, contracts, certificates,
invoices, and payment requests must be verified with the issuer.

## Data Privacy Act alignment

The design supports transparency, legitimate purpose, proportionality, data
minimization, retention, security, and data-subject deletion. The project team
must still complete a Privacy Impact Assessment, assign a responsible privacy
contact, review processor terms, document incident response, and obtain school
or legal review before treating this document as a complete compliance finding.
