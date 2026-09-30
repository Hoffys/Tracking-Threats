# Detection evaluation

SYNTHETIC regression fixtures only. These metrics are not real-world accuracy estimates. Independent real-world evaluation is outstanding.

Captured: 2026-09-30T05:29:56.942Z. Scanner: baseline. Selected split: all.

Dataset fingerprint: `49f78d2c9a91c1063477e439f49f5576590b5b5a3eb2e50813c093ec6d2e28d4`.

Scores are safety scores: warning = score < warningBelow (includes blocks); block = score <= blockAtMost. Thresholds are evaluator policies, not production configuration changes.

| Split | Policy | TP | FP | TN | FN | Precision | Recall | FPR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| tuning | warning | 10 | 5 | 10 | 5 | 66.67% | 66.67% | 33.33% |
| tuning | block | 10 | 0 | 15 | 5 | 100.00% | 66.67% | 0.00% |
| held-out | warning | 8 | 7 | 8 | 7 | 53.33% | 53.33% | 46.67% |
| held-out | block | 6 | 0 | 15 | 9 | 100.00% | 40.00% | 0.00% |

Undefined ratios have a zero denominator; they are not silently converted to zero or 100%.

One serial call per case using performance.now(), in milliseconds; imports, validation and reporting excluded. No warmup; order, JIT, host load and instrumentation affect timings. Not endpoint/network or throughput latency.

| Split | Calls | Mean ms | P50 ms | P95 ms | Max ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| tuning | 30 | 0.1667 | 0.0849 | 0.5769 | 1.0026 |
| held-out | 30 | 0.0390 | 0.0288 | 0.1140 | 0.1431 |

## Misses and false positives (IDs only)

- tuning, warning: FP = T-url-01, T-url-02, T-url-05, T-message-01, T-email-04; FN = T-url-08, T-url-10, T-message-09, T-email-08, T-email-10.
- tuning, block: FP = none; FN = T-url-08, T-url-10, T-message-09, T-email-08, T-email-10.
- held-out, warning: FP = H-url-03, H-url-04, H-url-05, H-message-01, H-message-02, H-message-03, H-email-04; FN = H-url-09, H-url-10, H-message-09, H-message-10, H-email-07, H-email-09, H-email-10.
- held-out, block: FP = none; FN = H-url-06, H-url-09, H-url-10, H-message-08, H-message-09, H-message-10, H-email-07, H-email-09, H-email-10.
