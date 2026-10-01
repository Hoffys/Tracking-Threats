# Detection evaluation

SYNTHETIC regression fixtures only. These metrics are not real-world accuracy estimates. Independent real-world evaluation is outstanding.

Captured: 2026-10-01T09:00:14.636Z. Scanner: production-shared/production. Selected split: all.

Dataset fingerprint: `8c7cd35eef38fe8bad69a7913b11b5e1622828669c2309335d23e3c84157132d`.

Primary warning: Appears Safe (80–100) = Negative; Caution (>50 and <80) and Risk Detected (0–50) = Positive. Secondary block: Caution = Negative. Scores are safety scores, not probabilities.

| Split | Policy | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 | FPR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| tuning | warning | 4 | 0 | 6 | 0 | 100.00% | 100.00% | 100.00% | 100.00% | 0.00% |
| tuning | block | 4 | 0 | 6 | 0 | 100.00% | 100.00% | 100.00% | 100.00% | 0.00% |
| held-out | warning | 2 | 0 | 4 | 4 | 60.00% | 100.00% | 33.33% | 50.00% | 0.00% |
| held-out | block | 2 | 0 | 4 | 4 | 60.00% | 100.00% | 33.33% | 50.00% | 0.00% |

Undefined ratios have a zero denominator; they are not silently converted to zero or 100%.

One serial call per case using performance.now(), in milliseconds; imports, validation and reporting excluded. No warmup; order, JIT, host load and instrumentation affect timings. Not endpoint/network or throughput latency.

| Split | Calls | Mean ms | P50 ms | P95 ms | Max ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| tuning | 10 | 338.9357 | 0.7008 | 1574.0694 | 1574.0694 |
| held-out | 10 | 1075.6334 | 410.0572 | 5491.3781 | 5491.3781 |

## Confusion matrix: warning

| Predicted / Actual | Malicious | Legitimate |
| --- | ---: | ---: |
| Malicious | 6 | 0 |
| Legitimate | 4 | 10 |

## Confusion matrix: block

| Predicted / Actual | Malicious | Legitimate |
| --- | ---: | ---: |
| Malicious | 6 | 0 |
| Legitimate | 4 | 10 |

## Misses and false positives (IDs only)

- tuning, warning: FP = none; FN = none.
- tuning, block: FP = none; FN = none.
- held-out, warning: FP = none; FN = H-url-10, H-message-08, H-url-09, H-message-09.
- held-out, block: FP = none; FN = H-url-10, H-message-08, H-url-09, H-message-09.
