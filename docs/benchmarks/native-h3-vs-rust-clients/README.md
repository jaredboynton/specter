# Native H3 vs Rust Clients Benchmark Artifacts

Date: 2026-05-24

## Gate Semantics

- The `superiority_gate` covers HTTP/3 request/response rows only.
- Required H3 comparators are `quiche_direct`, `tokio_quiche`, `h3_quinn`, and `reqwest_h3`.
- `quinn_transport` and `s2n_quic_transport` are QUIC transport-only baselines and are not part of the H3 HTTP gate.
- RFC 9220 rows are raw WebSocket-over-H3 tunnel workload proof. `quiche` and `tokio-quiche` now have measured low-level tunnel rows, but tunnel superiority still needs its own p99-scale gate before publication.

## Current Proof

- `2026-05-24-rfc9220-n100.json` is the current release-grade proof artifact and is the first artifact with n=100 samples for every measured row.
- It was produced from n=100 per-client fixture runs (`--warmups 5 --samples 100`) for `specter_native`, `specter_native_rfc9220_tunnel`, `specter_native_rfc9220_tunnel_close`, `specter_native_rfc9220_tunnel_mixed`, `quiche_direct_rfc9220_tunnel`, `tokio_quiche_rfc9220_tunnel`, `quiche_direct`, `tokio_quiche`, `h3_quinn`, `reqwest_h3`, and `quinn_transport`, then merged through the benchmark import-precedence path.
- The gate passes with `specter_native_is_faster_than_required_h3_competitors`; fastest non-Specter required H3 row is `reqwest_h3`.
- Every measured row carries `sample_count = 100`, so the artifact is statistically meaningful at p99 for all reported rows.
- `fixture_events` is empty because the n=100 artifact is a per-client merge, not a same-process all-client capture.
- The previous n=30 release-grade artifact `2026-05-24-full-local-n30.json` remains in the directory as historical context.

## Non-Gate Rows

- Specter RFC 9220 rows cover raw tunnel echo, client DATA+FIN/server FIN, and a slow-consumer tunnel plus concurrent H3 streaming workload at n=100 in `2026-05-24-rfc9220-n100.json`.
- `quiche_direct_rfc9220_tunnel` and `tokio_quiche_rfc9220_tunnel` are now real measured rows; `2026-05-24-rfc9220-n100.json` reports them at n=100 alongside the Specter tunnel rows.
- The Specter RFC 9220 tunnel adapters reuse one Specter `Client` across warmups and samples, while the `quiche_direct_rfc9220_tunnel` and `tokio_quiche_rfc9220_tunnel` adapters open a fresh QUIC connection per sample. Both are valid per-request comparators; cross-adapter throughput numbers should be read with that asymmetry in mind, and a connection-amortized RFC 9220 comparator is a future improvement.
- `h3_quinn_rfc9220_tunnel`, `reqwest_h3_rfc9220_tunnel`, `tokio_tungstenite_rfc9220`, and `reqwest_rfc9220` remain `unsupported_by_client` capability-audit rows because their public APIs do not expose an RFC 9220 tunnel surface.
- `s2n_quic_transport` is measured in `2026-05-24-full-local-with-s2n-smoke.json` and `2026-05-24-s2n-quic-transport-local.json`.

## Follow-Ups

- Produce a same-process all-client run that keeps measured rows and captures in-process `fixture_events`.
- Add a dedicated RFC 9220 tunnel superiority gate if the project wants to publish a Specter-vs-`quiche`/`tokio-quiche` raw tunnel win; keep it behind its own flag so it cannot regress the HTTP/3 gate.
- Add a connection-amortized RFC 9220 comparator path (or amortize the Specter tunnel rows by opening one connection per sample) so the third-party tunnel rows are directly comparable to Specter's reused-connection numbers.
