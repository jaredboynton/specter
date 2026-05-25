# Specter Native H3 Remaining Gap Ledger

Date: 2026-05-25
Repo: `/Users/jaredboynton/__devlocal/specter`

## Read This First

This is the current native H3 gap ledger. It is intentionally not a change log.

- Active gaps are the only items listed under `Active Gaps`.
- Solved items moved to `Closed Gaps / Regression Guards`.
- Historical benchmark commands and long per-patch notes belong in artifacts, tests, or `CHANGELOG.md`, not in this ledger.
- Runtime native H3 remains hand-rolled; `quiche`, `tokio-quiche`, `h3-quinn`, `reqwest_h3`, `quinn`, and `s2n-quic` are benchmark/comparator surfaces unless explicitly noted as transport-only baselines.

## Claim Boundary

| Area | Current claim | Proof | Still caveated |
|---|---|---|---|
| Native H3 HTTP | Specter beats required Rust H3 HTTP comparator rows in local same-fixture runs. | `docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-n100-plus-close-and-mixed-comparators.json` has `superiority_gate.pass = true`, required rows present, and zero fixture events. | Keep repeated/CI fixture runs treating fatal fixture events as blockers. |
| RFC9220 echo tunnel | Specter beats low-level `quiche` and `tokio-quiche` echo tunnel rows. | Same combined artifact has `rfc9220_tunnel_superiority_gate.pass = true` with n=100 echo rows. | Gate covers echo only. |
| RFC9220 close/FIN | Specter and low-level comparator rows exist. | Same combined artifact has Specter n=100 and `quiche`/`tokio-quiche` n=30 close rows. | Not yet part of a full-suite superiority gate. |
| RFC9220 mixed slow-consumer | Specter and low-level comparator rows exist. | Same combined artifact has Specter n=100 and `quiche`/`tokio-quiche` n=30 mixed rows. | Specter does not yet beat low-level `quiche` on mixed p50/p95, so no suite-wide superiority claim. |
| QUIC transport-only baselines | `quinn_transport` and optional `s2n_quic_transport` have measured echo adapters. | `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-quic-transport-local.json`, `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-s2n-quic-transport-local.json`, and smoke artifacts. | They are not H3 rows and are outside H3 superiority gates. |
| Runtime dependency boundary | Native H3/QUIC runtime is not shelled out to `quiche` or `h3-quinn`. | Runtime lives under `src/transport/h3/`; third-party H3 clients live in `benches/native_h3_vs_rust_clients/`. | BoringSSL remains the TLS backend; TLS fingerprinting is constrained by its ClientHello machinery where noted below. |

## Active Gaps

| Priority | Gap | Current state | Next proof needed |
|---|---|---|---|
| P0 | RFC9220 full tunnel-suite superiority | Echo gate passes. Close/FIN and mixed rows exist. Mixed workload remains unproven against low-level `quiche` p50/p95. | Expand the gate to echo + close/FIN + mixed only after mixed is optimized or the claim is narrowed with an explicit metric boundary. |
| P1 | Native QUIC path migration completion | PATH_CHALLENGE/PATH_RESPONSE token handling, CID inventory primitives, anti-amplification primitives, 1-RTT CID routing, post-validation client DCID promotion, migrated peer-address acceptance, server-side post-handshake `NEW_CONNECTION_ID` packetization, and same-fixture migration-CID routing are implemented. | Driver/server integration for outbound-builder anti-amplification gating and full server-side migration lifecycle. |
| P1 | Recovery soak/backoff validation | RFC9002-style recovery/PTO implementation is wired through client/server packet spaces and app data retransmit paths. | Longer soak/backoff runs that exercise repeated loss, PTO backoff/reset, persistent congestion, and server/client app-space retransmission under load. |
| P2 | Browser ACK parity | Threshold + `max_ack_delay_ms` timer paths exist for client/server/fixture, including tuned benchmark profile support. | Capture Chrome/Firefox QUIC ACK thresholds/delays by version and compare against Specter defaults and `ack_eliciting_threshold = 128`. |
| P2 | TLS/H3 capture presets | Certificate compression, deterministic-vs-browser-permuted extension policy, raw ordered transport parameters, session replay, and 0-RTT controls exist. | Capture-derived raw transport-parameter presets and explicit extension-list ordering beyond BoringSSL permutation policy. |
| P2 | Public capacity APIs | Internal byte-bounded H3 body/tunnel flow control and fair send scheduling exist. | Public byte-level pending/backpressure metrics for RFC9220 and unified H1/H2/H3 capacity knobs where API consumers need them. |

## Closed Gaps / Regression Guards

Keep these under regression coverage; do not relist them as active gaps.

| Area | Closed state |
|---|---|
| Same-fixture H3 HTTP proof | Required rows for `specter_native`, `quiche_direct`, `tokio_quiche`, `h3_quinn`, and `reqwest_h3` are measured with the H3 superiority gate passing. |
| `tokio_quiche` body/FIN blocker | Latest persisted full same-fixture proofs emit no fixture events; the previous body timeout is not reproducing in current artifacts. |
| Fixture event classification | Fixture events serialize stable `category` and `fatal` fields; current release artifacts have zero events. |
| QUIC connection IDs | Required server transport parameters include original-destination, initial-source, and retry-source CIDs; server/client 1-RTT routing uses the expected CIDs. |
| Retry and Version Negotiation | Retry integrity, Retry-driven Initial restart, VN-driven version selection/restart, loop guards, and no-overlap errors are implemented. |
| PATH_CHALLENGE primitives | Client packetization and matching PATH_RESPONSE validation are implemented; remaining work is migration lifecycle, not token handling. |
| Post-handshake NEW_CONNECTION_ID | `NativeQuicServerHandshake::build_server_new_connection_id_packet` can issue migration CIDs after application keys, and the local same-fixture server advertises/registers a migration CID after HandshakeDone. |
| RFC9002 recovery/PTO core | Per-space RTT/PTO/loss state, congestion response, CRYPTO PTO retransmission, app-space PTO, and mock/same-fixture server wake paths are implemented. |
| Close drain | Client, mock-server, and same-fixture server retain/replay protected `CONNECTION_CLOSE` packets during bounded drain windows and suppress non-close sends after draining. |
| Key update | 1-RTT key update has traffic-secret/key-phase rotation, previous-key retention, and local-update ACK gating. |
| ACK_ECN and ECN marking | ACK_ECN encode/decode, counter validation, CE growth tracking, congestion response, socket receive ECN reporting, and fingerprint-controlled outbound ECN marking are implemented. |
| PMTU probing | Native H3 has probe policy, PING+PADDING probes, ACK-only promotion, and loss-driven search-ceiling reduction. |
| ACK timer/decimation | Pending ACKs flush on `max_ack_delay_ms`; idle handling treats delayed ACKs as driver work. |
| TLS features | Certificate compression, session-ticket capture/replay, `NativeH3SessionCache`, 0-RTT opt-in policy, and handshake-status reporting are wired. |
| Raw ordered transport parameters | Caller-supplied raw ordered QUIC transport parameter lists encode in order with dynamic CID placeholders and pool-key separation. |
| H3 scheduling/fairness | Request-body/tunnel DATA class rotation, per-stream rotation, adaptive DATA budgets, and origin-fair slow-path dispatch are implemented. |
| Flow control/backpressure | Streaming responses and RFC9220 tunnels release receive credit on public byte consumption; RFC9220 outbound sends use byte permits and release them on transmit. |
| RFC9220 comparator rows | Specter echo/close/mixed rows and low-level `quiche`/`tokio-quiche` echo/close/mixed rows are persisted; only full-suite superiority remains open. |
| Transport-only adapters | `quinn_transport` and optional `s2n_quic_transport` have measured rows and are explicitly outside H3 superiority gates. |

## Current Proof Artifacts

| Artifact | Purpose | Gate/sample note |
|---|---|---|
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-n100-plus-close-and-mixed-comparators.json` | Current combined H3 HTTP + RFC9220 proof artifact. | H3 HTTP gate passes; RFC9220 echo gate passes; zero fixture events; close/mixed rows included but not suite-gated. |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-n100.json` | RFC9220 p99-scale Specter echo/close/mixed plus low-level echo comparators. | n=100 rows; echo gate passes. |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-n100-plus-close-comparators.json` | Adds low-level close/FIN comparators. | `quiche`/`tokio-quiche` close rows are n=30. |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30-plus-rfc9220-comparators.json` | Earlier release-grade native H3 HTTP proof plus RFC9220 rows. | H3 HTTP gate passes; retained for historical comparison. |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-with-s2n-smoke.json` | Same-fixture smoke including optional `s2n_quic_transport`. | Smoke-scale measured rows, not the release gate. |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-quic-transport-local.json` | Transport-only `quinn_transport`/`s2n_quic_transport` baseline. | Lower-layer echo rows only. |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-s2n-quic-transport-local.json` | Optional `s2n_quic_transport` baseline. | Lower-layer echo row only. |

## Current RFC9220 Rows

Rows below are from `docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-n100-plus-close-and-mixed-comparators.json`.

| Row | Samples | p50 TTFT ns | p95 TTFT ns | bytes/sec | Status |
|---|---:|---:|---:|---:|---|
| `specter_native_rfc9220_tunnel` | 100 | 225,500 | 375,083 | 4,252,954 | Echo gate baseline. |
| `quiche_direct_rfc9220_tunnel` | 100 | 2,741,416 | 2,849,625 | 372,260 | Echo comparator. |
| `tokio_quiche_rfc9220_tunnel` | 100 | 4,012,083 | 4,621,291 | 236,301 | Echo comparator. |
| `specter_native_rfc9220_tunnel_close` | 100 | 345,709 | 1,050,333 | 2,167,553 | Close/FIN measured. |
| `quiche_direct_rfc9220_tunnel_close` | 30 | 2,982,375 | 4,280,083 | 332,230 | Close/FIN comparator. |
| `tokio_quiche_rfc9220_tunnel_close` | 30 | 3,342,208 | 3,625,042 | 305,898 | Close/FIN comparator. |
| `specter_native_rfc9220_tunnel_mixed` | 100 | 8,888,959 | 24,354,042 | 984,668 | Mixed workload measured; not superior to `quiche` on latency. |
| `quiche_direct_rfc9220_tunnel_mixed` | 30 | 3,044,500 | 3,183,875 | 662,382 | Mixed comparator. |
| `tokio_quiche_rfc9220_tunnel_mixed` | 30 | 92,553,000 | 102,379,292 | 963,604 | Mixed comparator. |

Unsupported RFC9220 capability-audit rows remain explicit non-comparators: `h3_quinn_rfc9220_tunnel`, `reqwest_h3_rfc9220_tunnel`, `tokio_tungstenite_rfc9220`, and `reqwest_rfc9220`.

## Next Execution Order

1. Expand the RFC9220 gate only after the suite claim is well-defined and mixed workload behavior is fixed or explicitly scoped.
2. Finish path migration driver/server integration: anti-amplification gating and server migration lifecycle.
3. Run recovery soak/backoff validation across repeated loss, PTO, app retransmission, and persistent congestion cases.
4. Capture browser ACK behavior and calibrate native ACK thresholds/timers against Chrome/Firefox versions.
5. Add capture-derived TLS/H3 presets for raw transport parameters and extension ordering where BoringSSL allows control.
6. Promote public RFC9220 queued-byte/backpressure metrics if API consumers need unified capacity reporting.

## Validation Commands

Use these to refresh the ledger when code changes:

```bash
jq '{fixture_events: (.fixture_events|length), h3_gate: .superiority_gate.pass, rfc9220_gate: .rfc9220_tunnel_superiority_gate.pass}' \
  docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-n100-plus-close-and-mixed-comparators.json
```

```bash
jq '.rows[] | select(.competitor_id|test("^(specter_native|quiche_direct|tokio_quiche|h3_quinn|reqwest_h3|quinn_transport|s2n_quic_transport|.*rfc9220.*)$")) |
  {id:.competitor_id,status,samples:.sample_count,p50:.p50_ttft_ns,p95:.p95_ttft_ns,bps:.bytes_per_sec}' \
  docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-n100-plus-close-and-mixed-comparators.json
```

```bash
git diff --check -- docs/specter-native-h3-remaining-seams.md docs/specter-websocket-h3-current-status-and-gap-plan.md
```
