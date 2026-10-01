# Detection evaluation

SYNTHETIC regression fixtures only. These metrics are not real-world accuracy estimates. Independent real-world evaluation is outstanding.

Captured: 2026-10-01T08:59:34.479Z. Scanner: production-shared/local. Selected split: all.

Dataset fingerprint: `49f78d2c9a91c1063477e439f49f5576590b5b5a3eb2e50813c093ec6d2e28d4`.

Primary warning: Appears Safe (80–100) = Negative; Caution (>50 and <80) and Risk Detected (0–50) = Positive. Secondary block: Caution = Negative. Scores are safety scores, not probabilities.

| Split | Policy | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 | FPR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| tuning | warning | 12 | 0 | 15 | 3 | 90.00% | 100.00% | 80.00% | 88.89% | 0.00% |
| tuning | block | 11 | 0 | 15 | 4 | 86.67% | 100.00% | 73.33% | 84.62% | 0.00% |
| held-out | warning | 8 | 0 | 15 | 7 | 76.67% | 100.00% | 53.33% | 69.57% | 0.00% |
| held-out | block | 8 | 0 | 15 | 7 | 76.67% | 100.00% | 53.33% | 69.57% | 0.00% |

Undefined ratios have a zero denominator; they are not silently converted to zero or 100%.

One serial call per case using performance.now(), in milliseconds; imports, validation and reporting excluded. No warmup; order, JIT, host load and instrumentation affect timings. Not endpoint/network or throughput latency.

| Split | Calls | Mean ms | P50 ms | P95 ms | Max ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| tuning | 30 | 0.6011 | 0.2701 | 3.0316 | 3.2195 |
| held-out | 30 | 0.8490 | 0.3180 | 4.0495 | 6.6571 |

## Confusion matrix: warning

| Predicted / Actual | Malicious | Legitimate |
| --- | ---: | ---: |
| Malicious | 20 | 0 |
| Legitimate | 10 | 30 |

## Confusion matrix: block

| Predicted / Actual | Malicious | Legitimate |
| --- | ---: | ---: |
| Malicious | 19 | 0 |
| Legitimate | 11 | 30 |

## Misses and false positives (IDs only)

- tuning, warning: FP = none; FN = T-message-09, T-url-10, T-email-08.
- tuning, block: FP = none; FN = T-url-09, T-message-09, T-url-10, T-email-08.
- held-out, warning: FP = none; FN = H-url-10, H-message-08, H-url-09, H-message-09, H-email-10, H-email-09, H-message-10.
- held-out, block: FP = none; FN = H-url-10, H-message-08, H-url-09, H-message-09, H-email-10, H-email-09, H-message-10.
