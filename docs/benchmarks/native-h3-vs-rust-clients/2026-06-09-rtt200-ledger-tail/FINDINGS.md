# GET p95 ledger-paced tail at RTT 200us: the zero-RTT-artifact thesis is refuted

Date: 2026-06-09. Tree: 2406de6 (includes the out-of-order reassembly fix that made
this measurable; before it, Specter DNF'd every netem run -- see
`2026-06-09-rtt-reorder-reassembly-fix/FINDINGS.md`). Host: awsdev (Graviton4,
EC2 Spot, quiet).

## Status: non-publishable diagnostic

This run modifies the network environment (`tc qdisc add dev lo root netem delay
200us`), which the provenance stamp cannot capture, so it must never feed README
claims. Method: direct per-client bench invocations with fixture-ledger capture,
`--warmups 0 --samples 100`, 3 reps, publishable Specter GET profile (IDLE_GET=1,
GET_EPOCH=1, IO_EPOCH=0, spin 25us), fixture process/core2/inline-first-chunk-v1.
warmups=0 because the ledger response-count contract takes warmup counts from
`SPECTER_BENCH_RUN_PROVENANCE`, and fabricating that stamp for a diagnostic would
be a benchmark-truth violation; all clients run identical conditions so the
comparison is fair.

## Question

Is Specter's RTT~0 GET ledger-paced-tail loss (~23us vs tokio ~15us at the canonical
gate) a zero-RTT measurement artifact that disappears at real network latency?

## Result: no. The loss persists at RTT 200us with the same shape.

p50 / p95 ledger-paced tail overhead (us), reps 1/2/3, n=100 each:

| client        | p50 r1 | p50 r2 | p50 r3 | p95 r1 | p95 r2 | p95 r3 |
|---------------|--------|--------|--------|--------|--------|--------|
| specter_native| 17.9   | 20.5   | 15.7   | 55.1   | 49.6   | 46.5   |
| tokio_quiche  | 12.9   | 14.8   | 13.5   | 31.5   | 48.7   | 37.9   |
| quiche_direct | 47.3   | 71.7   | 46.6   | 80.7   | 98.8   | 84.3   |
| h3_quinn      | 14.7   | 16.8   | 16.3   | 33.9   | 39.5   | 35.4   |
| reqwest_h3    | 14.8   | 15.1   | 17.4   | 37.5   | 34.6   | 33.7   |

p50 TTFB (us): specter 433.2-435.9 (best of five every rep, tied with quiche_direct),
h3_quinn 441-445, tokio 445-446, reqwest 452-453. Throughput: parity (15.9-16.4
MB/s all clients).

## Conclusions

1. The artifact thesis is refuted. Specter's tail deficit vs tokio_quiche is a
   consistent ~3-6us at p50 and ~10-15us at p95 at RTT 200us, matching the RTT~0
   gap. It is a real fixed per-sample recv-side overhead, present at any RTT.
2. Specter wins TTFB at real RTT and holds throughput parity; the tail is the one
   GET metric still lost, to tokio_quiche, h3_quinn, and reqwest_h3 (rep medians
   49.6 vs 37.9 / 35.4 / 34.6 p95).
3. quiche_direct's tail collapses at RTT (3-5x worse than at RTT~0, last place by
   far) while tokio_quiche on the same quiche library stays fast: the ledger tail
   is dominated by the event-loop/driver architecture around the QUIC stack. This
   is consistent with the architecture-wave finding that the remaining Specter
   deficit is loop-structural (single pinned timer + drain-to-quiescence in quinn
   and tokio-quiche vs Specter's per-iteration select! arms), and that closing it
   is an architectural change to the receive loop rather than another micro-lever.
4. Rep noise at RTT is large enough that Specter's best p95 (46.5) beats tokio's
   worst (48.7), but rep medians keep a clear ordering; do not cherry-pick reps.

Raw rows: /tmp/rtt_<client>_<rep>.json on awsdev at run time (not archived; this
file records the parsed numbers verbatim).
