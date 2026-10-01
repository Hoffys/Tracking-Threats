# Detection evaluation

External label independence is asserted by the importer, not verified by tooling. Dataset-specific metrics do not establish real-world accuracy; review sampling, provenance and temporal/organizational leakage.

Captured: 2026-10-01T08:59:59.374Z. Scanner: production-shared/production. Selected split: held-out.

Dataset fingerprint: `b5a413514353d28312c6c6c314a52729f30e7ef6e674ef17939d1741827f99bd`.

Primary warning: Appears Safe (80–100) = Negative; Caution (>50 and <80) and Risk Detected (0–50) = Positive. Secondary block: Caution = Negative. Scores are safety scores, not probabilities.

| Split | Policy | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 | FPR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| held-out | warning | 9 | 3 | 7 | 1 | 80.00% | 75.00% | 90.00% | 81.82% | 30.00% |
| held-out | block | 9 | 3 | 7 | 1 | 80.00% | 75.00% | 90.00% | 81.82% | 30.00% |

Undefined ratios have a zero denominator; they are not silently converted to zero or 100%.

One serial call per case using performance.now(), in milliseconds; imports, validation and reporting excluded. No warmup; order, JIT, host load and instrumentation affect timings. Not endpoint/network or throughput latency.

| Split | Calls | Mean ms | P50 ms | P95 ms | Max ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| held-out | 20 | 1217.8029 | 915.8397 | 2503.2207 | 2689.4640 |

## Confusion matrix: warning

| Predicted / Actual | Malicious | Legitimate |
| --- | ---: | ---: |
| Malicious | 9 | 3 |
| Legitimate | 1 | 7 |

## Confusion matrix: block

| Predicted / Actual | Malicious | Legitimate |
| --- | ---: | ---: |
| Malicious | 9 | 3 |
| Legitimate | 1 | 7 |

## Misses and false positives (IDs only)

- held-out, warning: FP = phiusiil-1290, phiusiil-1454, phiusiil-0984; FN = phiusiil-1916.
- held-out, block: FP = phiusiil-1290, phiusiil-1454, phiusiil-0984; FN = phiusiil-1916.
