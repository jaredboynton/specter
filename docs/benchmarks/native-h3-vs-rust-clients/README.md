# Native H3 vs Rust Clients Benchmark Artifacts

Date: 2026-06-09 (GET-only ledger repeat gate double pass and fair warm-vs-warm steadystate tunnel remeasure). Historical scout and iteration artifacts were pruned on 2026-06-09; this directory holds the current evidence chain plus two labeled regression fixtures.

## Gate Semantics

- The `superiority_gate` covers HTTP/3 request/response rows only.
- Required H3 comparators are `quiche_direct`, `tokio_quiche`, `h3_quinn`, and `reqwest_h3`.
- `quinn_transport` and `s2n_quic_transport` are measured QUIC transport-only baselines and are not part of the H3 HTTP gate.
- The GET-only ledger repeat gate (`GET_ONLY_GATE=1 GET_REPEAT_GATE=1`, `scripts/current_rows_awsdev.sh`) compares Warpsock's worst rep against each comparator's per-metric best rep on p50/p95 TTFB, ledger-paced throughput, and p50/p95 ledger-paced tail across 4 fresh-process reps per client; it fails closed on dirty trees, non-allowlisted environment, or missing fixture-ledger provenance, and rc=0 requires all four per-rep truth stamps plus the repeat truth stamp.
- The `rfc9220_full_suite_superiority_gate` covers the raw WebSocket-over-H3 tunnel echo, close/FIN, and slow-consumer mixed workloads and is separate from the H3 HTTP gate.
- Required RFC 9220 tunnel rows are the nine measured rows below, each with `status = "measured_pass"` and `sample_count >= 100`:
  - `warpsock_native_rfc9220_tunnel`, `warpsock_native_rfc9220_tunnel_close`, `warpsock_native_rfc9220_tunnel_mixed`
  - `quiche_direct_rfc9220_tunnel`, `quiche_direct_rfc9220_tunnel_close`, `quiche_direct_rfc9220_tunnel_mixed`
  - `tokio_quiche_rfc9220_tunnel`, `tokio_quiche_rfc9220_tunnel_close`, `tokio_quiche_rfc9220_tunnel_mixed`
- Warpsock must beat each matching comparator row on p50 TTFB, p95 TTFB, and bytes/sec for every workload pair.

## Current Proof (2026-06-09 GET-only ledger repeat gate, two consecutive passes)

- Artifact dirs `2026-06-09-direct-get-clientpin-clean-gate/` and `2026-06-09-direct-get-clientpin-clean-gate-r2/`, owned-tree HEAD `ba356d7`, quiet Graviton4 Spot host (IMDSv2 instance-life-cycle verified `spot`). Each gate: 4 fresh-process reps per client, n=100 plus 10 warmups, 80 KiB paced streaming GET (fixture emission span ~4.6 ms), shipping Chrome ACK cadence, warm connection reuse, fixture process pinned to core 2, every client process pinned to cores 4-11. Both gates wrote all four per-rep truth stamps plus the repeat truth stamp (rc=0).
- Gate 1 worst-vs-best (TTFB p50/p95, ledger MiB/s, ledger tail p50/p95): Warpsock worst rep 37.6 us / 45.3 us / 19.354 / 1.0 us / 7.2 us. Comparator per-metric best reps: `tokio_quiche` 39.6 / 51.6 / 19.291 / 2.0 / 9.0; `h3_quinn` 44.6 / 57.8 / 19.270 / 3.4 / 14.1; `reqwest_h3` 47.9 / 81.5 / 19.234 / 2.8 / 13.0; `quiche_direct` 46.5 / 80.4 / 19.123 / 16.0 / 51.8.
- Gate 2 reproduces: Warpsock worst rep 32.5 / 43.5 / 19.363 / 2.9 / 7.4 vs bests `tokio_quiche` 39.4 / 47.1 / 19.288 / 5.1 / 12.5; `h3_quinn` 41.1 / 48.3 / 19.275 / 9.2 / 17.6; `reqwest_h3` 47.9 / 63.3 / 19.256 / 4.1 / 14.0; `quiche_direct` 49.3 / 80.1 / 19.127 / 10.5 / 39.4.
- Cause chain: deferred boundary-ACK send (`9aa436b`), GET-burst drain to quiescence before wire maintenance plus pinned epoch timer (`b23ef2c`), single-copy 1-RTT datagram decode (`ff6f467`), and identical client-process placement for all five clients in the harness (`ba356d7`). The placement control matters for gate truth: with client placement floating, scheduler wake-affinity handed individual comparator reps a cache-hot placement next to the pinned fixture, producing sub-1 us best-rep tail floors (reqwest_h3 961 ns) that no controlled placement reproduces, and the worst-vs-best criterion let that lottery decide gate outcomes in both directions.

## Current Proof (2026-06-09 fair warm-vs-warm steadystate)

- Artifact dir `2026-06-09-pmtu-probe-tunnel-defer/` (FINDINGS.md + echo-warpsock-rep1.json + echo-tokio-rep1.json), owned-tree HEAD `5e0d429`. Measured on the quiet AWS Graviton4 Spot host with `BENCH_TUNNEL_STEADYSTATE=1`, which opens ONE warm Extended-CONNECT tunnel per client and times per-message round-trip latency, so every client (Warpsock and the comparators alike) is measured warm-vs-warm. This removes the connection-reuse asymmetry that qualified the earlier warm-vs-cold combined-capture numbers.
- Under the fair steadystate harness Warpsock holds the lower p95 round-trip tail on ALL THREE tunnel workloads, reversing the 4.2.1 CHANGELOG rationale ("tokio_quiche holds a lower p95 tail on the echo and client-DATA+FIN workloads"):
  - echo: Warpsock p95 40.3 us [38.6-43.3] vs `tokio_quiche` 51.2 us [48.3-55.7] -- NON-OVERLAPPING win (Warpsock worst rep 43.3 < tokio best rep 48.3, 8 reps). p50 (32.9 vs 32.4 us) and throughput (28.8 vs 28.4 MiB/s) are parity at the 1 KB single-frame payload, Warpsock's known sub-MTU regime.
  - client DATA+FIN (close): Warpsock p50 69.7 / p95 80.1 [74.9-89.8] / tput 13.5 MiB/s vs `tokio_quiche` 75.3 / 101.9 [97.6-111.2] / 12.4 -- WIN on all three (p95 non-overlapping). `quiche_direct` ~3.35 ms.
  - slow-consumer mixed: Warpsock p50 37.1 / p95 42.3 [39.4-48.2] vs `tokio_quiche` 63.6 / 68.1 [63.3-69.8] -- WIN p50 and p95 (non-overlapping); throughput parity. `quiche_direct` ~3.40 ms.
- Root cause + fix (commit `5e0d429`): two deterministic ~100 us spikes per echo run were DPLPMTUD path-MTU probe packets (a large build + AEAD seal + send_to) emitted inline on the tunnel recv->send turn. `native_driver.rs` now defers probing while a tunnel has had activity within `PMTU_TUNNEL_IDLE_GAP` (2 ms); spike count 2 -> 0, echo p99 ~103 -> ~43 us. A flow-control hypothesis was falsified by experiment before this fix landed. Wire/fingerprint unchanged (probe cadence identical; only scheduling moves off the interactive path). GET / streaming connections (no open tunnel) probe immediately as before; the GET ledger tail beats all four comparators on p50 and p95 (regression check, 4 reps).
- The strict `rfc9220_full_suite_superiority_gate` still reports `fail`: it requires Warpsock to strictly beat each comparator on p50 AND p95 AND throughput for every workload, and echo p50/throughput are parity (not strictly better) at the 1 KB single-frame payload. The single-process combined all-client capture additionally does not run to completion in steadystate -- the `tokio_quiche_rfc9220_tunnel_mixed` adapter accumulates connection data past the fixture per-connection flow-control limit over a long reused tunnel and times out -- so the measurement basis here is per-workload isolated steadystate A/B (each workload its own process, symmetric warm-vs-warm for every client). The honest claim is therefore the p95-tail reversal above, not a full-suite pass.

## Retained Fixtures (combined capture and transport baselines)

- `2026-06-03-graviton4-suite-rep1.json` / `-rep2.json`: the most recent combined single-process all-client captures (H3 HTTP + RFC 9220 + transport rows), commit `25395a8`. Retained for the measured `quinn_transport` row and combined-capture provenance; their warm-vs-cold H3 HTTP and tunnel comparison numbers are superseded by the 2026-06-09 GET-only ledger repeat gate and the fair steadystate tunnel results above.
- `2026-05-25-rfc9220-suite-n100.json`: retained solely as the transport-baseline regression fixture; it is the artifact with both `quinn_transport` and `s2n_quic_transport` rows at `measured_pass`, guarded by `tests/h3_competitor_benchmark.rs` (`current_native_h3_suite_artifact_keeps_transport_baselines_measured`). Its Mac-sourced H3 and tunnel gate claims did not reproduce on the quiet Graviton4 host and are superseded by the sections above.

## Tunnel And Non-Gate Rows

- The Warpsock RFC 9220 mixed adapter now drives the concurrent H3 GET and tunnel CONNECT/send/drain from one start instant via `tokio::try_join!`, and measures mixed TTFB when streaming response headers arrive to match the low-level `quiche` adapter.
- The Warpsock RFC 9220 tunnel adapters reuse one Warpsock `Client` across warmups and samples, while the `quiche_direct_rfc9220_tunnel*` and `tokio_quiche_rfc9220_tunnel*` adapters open a fresh QUIC connection per sample. Both are valid per-request comparators; cross-adapter throughput numbers should be read with that asymmetry in mind. Setting `BENCH_TUNNEL_STEADYSTATE=1` removes the asymmetry -- every client (Warpsock and comparators) reuses ONE warm tunnel and is timed on per-message round-trips -- and is the basis for the 2026-06-09 fair result above.
- `h3_quinn_rfc9220_tunnel`, `reqwest_h3_rfc9220_tunnel`, `tokio_tungstenite_rfc9220`, and `reqwest_rfc9220` remain `unsupported_by_client` capability-audit rows because their public APIs do not expose an RFC 9220 tunnel surface.
- `quinn_transport` and `s2n_quic_transport` are measured non-gate transport rows in the current `2026-06-03-graviton4-suite-rep1.json` artifact, with older standalone transport artifacts retained as historical context.

## Follow-Ups

- Done (2026-06-03): the Graviton4 suite artifacts are same-process all-client captures, one process measuring every client per rep.
- Done (2026-06-09): the connection-amortized comparator is `BENCH_TUNNEL_STEADYSTATE=1` (all clients reuse one warm tunnel, symmetric per-message round-trips). Under it Warpsock wins the p95 tail on echo, close, AND mixed; the prior echo/close p95 losses were the warm-vs-cold asymmetry plus the now-fixed DPLPMTUD probe spike.
- Open: the combined single-process all-client capture cannot complete in steadystate because the `tokio_quiche_rfc9220_tunnel_mixed` adapter overruns the fixture per-connection flow-control limit on a long reused tunnel; raise that comparator adapter's connection flow-control window (or reset its tunnel periodically) so a single combined steadystate artifact can be captured.
