# Detection evaluation

SYNTHETIC regression fixtures only. These metrics are not real-world accuracy estimates. Independent real-world evaluation is outstanding.

Captured: 2026-10-01T08:49:40.401Z. Scanner: current. Selected split: all.

Dataset fingerprint: `49f78d2c9a91c1063477e439f49f5576590b5b5a3eb2e50813c093ec6d2e28d4`.

Scores are safety scores: warning = score < warningBelow (includes blocks); block = score <= blockAtMost. Thresholds are evaluator policies, not production configuration changes.

| Split | Policy | TP | FP | TN | FN | Precision | Recall | FPR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| tuning | warning | 12 | 0 | 15 | 3 | 100.00% | 80.00% | 0.00% |
| tuning | block | 11 | 0 | 15 | 4 | 100.00% | 73.33% | 0.00% |
| held-out | warning | 8 | 0 | 15 | 7 | 100.00% | 53.33% | 0.00% |
| held-out | block | 8 | 0 | 15 | 7 | 100.00% | 53.33% | 0.00% |

Undefined ratios have a zero denominator; they are not silently converted to zero or 100%.

One serial call per case using performance.now(), in milliseconds; imports, validation and reporting excluded. No warmup; order, JIT, host load and instrumentation affect timings. Not endpoint/network or throughput latency.

| Split | Calls | Mean ms | P50 ms | P95 ms | Max ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| tuning | 30 | 0.7113 | 0.3205 | 4.4394 | 5.4919 |
| held-out | 30 | 0.2985 | 0.2380 | 0.6437 | 0.6470 |

## Misses and false positives (IDs only)

- tuning, warning: FP = none; FN = T-url-10, T-message-09, T-email-08.
- tuning, block: FP = none; FN = T-url-09, T-url-10, T-message-09, T-email-08.
- held-out, warning: FP = none; FN = H-url-09, H-url-10, H-message-08, H-message-09, H-message-10, H-email-09, H-email-10.
- held-out, block: FP = none; FN = H-url-09, H-url-10, H-message-08, H-message-09, H-message-10, H-email-09, H-email-10.
