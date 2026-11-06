# Reviewed synthetic dataset v2

`reviewed-v2.jsonl` is an immutable, versioned copy of the 60 v1 synthetic cases. Existing IDs, splits, input strings, labels, scenario groups, and declared domains are retained. The two snapshot-backed cases have updated provenance rationales to describe the added test evidence. All original v1 fixture and historical report files remain unchanged.

## Case mapping and metric eligibility

| v2 case IDs | Source | Metric treatment | Review |
| --- | --- | --- | --- |
| All original IDs | `tuning.jsonl` and `held-out.jsonl` | Included unless listed below | IDs are preserved one-to-one. |
| `H-url-09` | `H-url-09` | Included | Adds sanitized structured page evidence for a password form submitting to another host. This lets the page-dependent scenario be evaluated offline. |
| `T-url-01` | `T-url-01` | Included | Adds a benign official account sign-in snapshot with an internal password form. Credential vocabulary alone is not labeled phishing. |
| `T-url-10` | `T-url-10` | Diagnostic-only | URL alone cannot establish the asserted credential-collection behavior. |
| `H-url-10` | `H-url-10` | Diagnostic-only | URL alone cannot establish the asserted malicious consent flow. |
| `H-message-10` | `H-message-10` | Diagnostic-only | The text requests approval, but does not establish the asserted IT impersonation or attacker flow. |
| `T-email-08` | `T-email-08` | Diagnostic-only | The transfer request is visible, but the asserted executive impersonation depends on sender context not established by the fixture. |
| `H-email-09` | `H-email-09` | Diagnostic-only | The beneficiary-change request is visible, but the asserted vendor impersonation depends on identity context not established by the fixture. |
| `H-email-10` | `H-email-10` | Diagnostic-only | The QR attachment and destination are absent from the text-only input. |

Diagnostic-only cases still run through their normal detector and appear in predictions/analyses with their original expected labels. They are excluded from TP, FP, TN, FN, accuracy, precision, recall, F1, FPR, and latency denominators. The report lists their IDs and review reasons.

## Controlled snapshot format

Snapshots contain only bounded, sanitized indicators: generic title text, counts of password fields/forms/external form actions/hidden frames, and booleans for credential language and obfuscated scripts. No HTML, captured URL, credentials, or live page content is stored. Evaluation uses local URL analysis and these indicators; it bypasses reputation providers and live page inspection for snapshot-backed rows.
