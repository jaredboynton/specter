# Streaming Benchmark Proof - 2026-05-24

This directory persists the final benchmark artifacts for Specter's local deterministic streaming comparison against `reqwest 0.12`.

## Scope

These results cover the `benches/streaming_vs_reqwest.rs` localhost fixtures for H1/H2 request-body and response-body streaming. They prove the configured benchmark gates on this machine and commit state; they are not a broad claim about every HTTP workload or network environment.

Gate requirements:

- Specter median TTFT improves by at least 5% over reqwest.
- Specter median throughput improves by at least 5% over reqwest.
- Paired Wilcoxon signed-rank p-values are below 0.01 for TTFT and throughput.
- p95 TTFT and p95 throughput regress by at most 5%.
- RFC 8441/WebSocket coexistence does not regress.

## Results

| Workload | Protocol | Samples | TTFT Improvement | Throughput Improvement | TTFT p-value | Throughput p-value | p95 TTFT Regression | p95 Throughput Regression | Status |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Response-body streaming | H1 | 100 | +65.59% | +19.97% | 0 | 4.44e-16 | -63.82% | -16.87% | pass |
| Response-body streaming | H2 | 100 | +26.12% | +7.88% | 0 | 4.05e-8 | -27.74% | -3.47% | pass |
| Request-body streaming | H1 | 100 | +10.34% | +11.53% | 3.35e-12 | 8.77e-13 | -3.08% | -13.03% | pass |
| Request-body streaming | H2 | 100 | +17.27% | +20.87% | 4.44e-16 | 0 | -27.56% | -20.15% | pass |

Negative p95 regression means Specter's p95 latency was lower, or its p95 throughput was higher, than reqwest's p95 value.

## Request-Body Measurement

The request-body gate remains the fixed 8-request workload with 5 chunks of `1024B` and `2ms` inter-chunk pacing. The request-body denominator now uses the fixture upload-complete timestamp as the final endpoint; response headers are only a counted fallback. Both request-body release artifacts report:

| Protocol | Denominator Floor Count | Client-Write Floor Count | Upload-Complete Fallback Count |
| --- | ---: | ---: | ---: |
| H1 | 0 | 0 | 0 |
| H2 | 0 | 0 | 0 |

## H2 Response Repeats

The H2 response win was repeated after the final hot-path fix to avoid publishing a one-off result.

| Artifact | Samples | Throughput Improvement | Throughput p-value | p95 Throughput Regression | Status |
| --- | ---: | ---: | ---: | ---: | --- |
| [`final2-h2-response-s100.json`](./final2-h2-response-s100.json) | 100 | +7.88% | 4.05e-8 | -3.47% | pass |
| [`final2-h2-response-repeat1-s100.json`](./final2-h2-response-repeat1-s100.json) | 100 | +5.71% | 1.48e-6 | -3.59% | pass |
| [`final2-h2-response-repeat2-s100.json`](./final2-h2-response-repeat2-s100.json) | 100 | +7.82% | 1.04e-8 | -6.24% | pass |
| [`final2-h2-response-repeat3-s100.json`](./final2-h2-response-repeat3-s100.json) | 100 | +6.66% | 9.97e-9 | -7.02% | pass |

The weakest H2 response repeat is still above the required 5% median-throughput win and below the required 0.01 Wilcoxon p-value.

## RFC 8441 Coexistence

Each final H1/H2 benchmark artifact includes `rfc8441_coexistence.status = "pass"` and `contamination_detected = false`. The H2 direct response path is opt-in for the benchmarked response-only hot path, while ordinary H2 multiplexing and RFC 8441/WebSocket reuse stay on the default pooled path.

## Artifacts

- [`summary.json`](./summary.json) - compact machine-readable summary.
- [`final2-h1-request-s100.json`](./final2-h1-request-s100.json) - raw 100-sample H1 request-body artifact.
- [`final2-h2-request-s100.json`](./final2-h2-request-s100.json) - raw 100-sample H2 request-body artifact.
- [`final2-h1-response-s100.json`](./final2-h1-response-s100.json) - raw 100-sample H1 response-body artifact.
- [`final2-h2-response-s100.json`](./final2-h2-response-s100.json) - raw 100-sample H2 response-body artifact.
- [`final2-h2-response-repeat1-s100.json`](./final2-h2-response-repeat1-s100.json) - first H2 response repeat.
- [`final2-h2-response-repeat2-s100.json`](./final2-h2-response-repeat2-s100.json) - second H2 response repeat.
- [`final2-h2-response-repeat3-s100.json`](./final2-h2-response-repeat3-s100.json) - third H2 response repeat.

The older combined `h1h2-*-pushdata-budget-s100.json` artifacts and standalone `rfc8441-pushdata-budget-live.json` were removed from this directory because they are superseded by these per-protocol final artifacts with corrected upload-complete request timing and embedded RFC 8441 coexistence evidence.

## Reproduction Commands

```bash
cargo bench --bench streaming_vs_reqwest -- --protocol h1 --request-body-streaming --samples 100 --warmups 5 --require-thresholds --json target/bench-results/final2-h1-request-s100.json
cargo bench --bench streaming_vs_reqwest -- --protocol h2 --request-body-streaming --samples 100 --warmups 5 --require-thresholds --json target/bench-results/final2-h2-request-s100.json
cargo bench --bench streaming_vs_reqwest -- --protocol h1 --response-body-streaming --samples 100 --warmups 5 --require-thresholds --json target/bench-results/final2-h1-response-s100.json
cargo bench --bench streaming_vs_reqwest -- --protocol h2 --response-body-streaming --samples 100 --warmups 5 --require-thresholds --json target/bench-results/final2-h2-response-s100.json
```

## Validation Commands

```bash
cargo test --test h2_inline_streaming -- --nocapture
cargo test --test validation_h2_streaming -- --nocapture
cargo test --test validation_h2_request_streaming -- --nocapture
cargo test rfc8441 -- --nocapture
cargo test --test benchmark_harness -- --nocapture
cargo test --test benchmark_thresholds -- --nocapture
cargo check --benches
```
