# Detection evaluation and acceptance

This is a pilot evaluation of **local heuristics**, not a claim of real-world phishing accuracy. No adviser-approved or independently labeled dataset was available. The 60 checked-in cases are authored synthetic scenarios: 30 tuning and 30 held-out, each with 15 phishing and 15 legitimate cases. Domain groups and scenario IDs cannot overlap splits. Neither real sites nor provider APIs are contacted by the evaluation runner.

## Reproduce

```sh
npm test
npm run evaluate:validate
npm run evaluate -- --split tuning
npm run evaluate -- --split held-out --baseline evaluation/baseline/report.json --out evaluation/results/new-run.json --markdown evaluation/results/new-run.md
```

Outputs must use unused filenames; the runner refuses to overwrite earlier reports. The default split is tuning. Do not tune thresholds or rules against the held-out results and continue calling those results independent. After using held-out failures for development, prepare a new independent holdout.

`evaluation/baseline/scanners/` contains the original synchronous scanners from commit `cfdff3d`, frozen before production scoring changes. Source hashes, dataset hashes, predictions, and the original report are retained. Current reports fingerprint the local scanner dependency graph, including the reviewed offline `tldts` PSL parser. The evaluation network guard is an accidental-network prevention measure, not a sandbox for untrusted programs.

## Recorded result: 2026-09-30

See [the detailed report](../evaluation/results/2026-09-30.md) and [machine-readable results](../evaluation/results/2026-09-30.json).

| Held-out policy | Before | After |
| --- | --- | --- |
| Phishing samples warned on | 8/15 | 8/15 |
| Legitimate samples incorrectly warned on | 7/15 | 0/15 |
| Phishing samples meeting block threshold | 6/15 | 8/15 |
| Legitimate samples meeting block threshold | 0/15 | 0/15 |
| Warning recall | 53.33% | 53.33% |
| Warning false-positive rate | 46.67% | 0% |

Seven phishing scenarios remain missed in the holdout. The observed precision is 100% on this small constructed sample, **not** 100% accuracy or an assurance about unseen attacks. This run supports fewer false alarms on these fixtures; it does not demonstrate improved overall warning recall. Current and baseline timing are single local calls, not controlled throughput or network benchmarks.

Warnings use score <80 and include blocked results; the block policy uses score <=50. A TP is labeled phishing flagged by that policy; FP is legitimate flagged; FN is phishing missed; TN is legitimate not flagged. Precision = TP/(TP+FP), recall = TP/(TP+FN), and FPR = FP/(FP+TN). Undefined denominators remain null. Reports separate warning and block policies, scanner type, and split, and expose misses by opaque case ID. Raw inputs are excluded from output reports.

## Import independently labeled data

The runner accepts one or more `--dataset path.jsonl` options. All files are validated together before filtering to a split. Each row must have these fields:

```json
{"id":"opaque-001","split":"tuning","kind":"url","label":"legitimate","scenario":"independent-scenario-001","domains":["example.com"],"input":"https://example.com/","provenance":{"type":"external-labeled","source":"Document the source and snapshot date","method":"independent-human","rationale":"Document independent evidence for this label"}}
```

`kind` is `url`, `message`, or `email`. URL/message inputs are strings; an email input is an object with `sender`, `subject`, and `body` strings. `label` is `phishing` or `legitimate`. External provenance methods are `independent-human` or `independent-source`. This schema records provenance; the tool cannot verify an author's independence. Obtain permission for data use and remove private message content before sharing a dataset. Keep imported private files outside this repository.

Reject ambiguous labels rather than labeling every unavailable or unlisted URL legitimate. Avoid deriving labels from the same providers being evaluated. Separate domains, campaigns, time windows, and duplicated/template messages between development and final test sets. Retain ambiguous/non-phishing threats in a separately labeled evaluation rather than pretending gambling or malware always means phishing. Record confidence intervals and dataset composition for a formal capstone evaluation; this pilot does not supply statistically representative estimates.

## Coverage and remaining scope

- Production URL checks combine local rules with bounded reputation lookups. Provider failures, disabled keys, skipped/unknown hashes, and offline mode are explicitly incomplete.
- Email/SMS checks enrich up to five unique links, with at most two links in flight. Reputation evidence cannot be averaged away by otherwise benign text. No-link messages remain local-only.
- URL rules use PSL registrable domains including private suffixes. Official-domain ownership suppresses only the corresponding brand-impersonation rule, not all checks.
- Generic login/bank/HTTP/suffix wording and gambling/piracy references alone do not establish phishing. Direct secret requests, destination deception, and provider evidence receive more weight.
- Page contents and HTTP redirects are **not fetched**. Rendered fake-login detection, sandboxed page inspection, QR/OCR, attachment execution, and SPF/DKIM/DMARC verification remain future work.
- Unit tests and a local browser acceptance run validate implementation behavior. A real extension enforcement test matrix and independent real-world detection dataset are still required before claiming broad protection effectiveness.
- The current score is a rule score, not a calibrated safety probability. A recorded block policy is not proof the browser prevented access.

Local URL and text findings deduct from 100. Message and email results retain the lowest score across content, sender, and inspected links, so averaging cannot hide a dangerous component. Provider deductions form a separate score; the final URL result is the lower of the local and provider scores. The URL and text rules are heuristic choices requiring independent validation; their weights are not learned probabilities.

The PSL parser uses [`tldts` with private suffix support](https://github.com/remusao/tldts). Reputation providers can return false positives or false negatives, as described in [Google Safe Browsing guidance](https://developers.google.com/safe-browsing/v4/usage-limits).

## Result wording update

Completed scans with internal status `Safe` now display **Appears safe**, regardless of provider availability. The detail panel states that the scan has finished and lists any unavailable, skipped, local-only, or unrecorded checks. This is a qualified assessment from the checks that ran, not a guarantee of safety or a claim that all providers responded. Caution/risk verdicts and failed-scan handling remain distinct. Scoring, provider results, and the recorded evaluation metrics are unchanged by this presentation update.
