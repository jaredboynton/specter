# Warpsock Native H3 Remaining Gap Ledger

Date: 2026-06-09

## Read This First

This is the current native H3 gap ledger. It is intentionally not a change log.

- Active gaps are the only items listed under `Active Gaps`.
- Solved items moved to `Closed Gaps / Regression Guards`.
- Historical benchmark commands and long per-patch notes belong in artifacts, tests, or `CHANGELOG.md`, not in this ledger.
- Runtime native H3 remains hand-rolled; `quiche`, `tokio-quiche`, `h3-quinn`, `reqwest_h3`, `quinn`, and `s2n-quic` are benchmark/comparator surfaces unless explicitly noted as transport-only baselines.

## Claim Boundary

| Area | Current claim | Proof | Still caveated |
|---|---|---|---|
| Native H3 HTTP GET | Warpsock worst rep beats every comparator per-metric best rep on p50/p95 TTFB, ledger-paced throughput, and p50/p95 ledger-paced tail across two consecutive fail-closed repeat gates. | `docs/benchmarks/native-h3-vs-rust-clients/2026-06-09-direct-get-clientpin-clean-gate/` and `-r2/` (rc=0, four per-rep truth stamps plus the repeat truth stamp each). | Loopback same-fixture GET at the shipping Chrome ACK cadence with warm reuse and controlled core placement for all clients; gate fails closed on dirty trees, non-allowlisted environment, or missing fixture-ledger provenance. |
| RFC 9220 full tunnel suite | Under the fair warm-vs-warm steadystate harness Warpsock holds the lower p95 round-trip tail on echo, close/FIN, and slow-consumer mixed; wins close on p50, p95, and throughput and mixed on p50 and p95; echo p50 and throughput are parity at the 1 KB single-frame payload. | `docs/benchmarks/native-h3-vs-rust-clients/2026-06-09-pmtu-probe-tunnel-defer/` | The strict `rfc9220_full_suite_superiority_gate` does not pass (echo p50/throughput parity is a tie, the gate demands strictly better), and the combined single-process steadystate capture cannot run to completion; see the benchmark README. |
| QUIC transport-only baselines | `quinn_transport` and `s2n_quic_transport` have measured echo adapters. | `docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-suite-n100.json` (regression fixture with both rows at `measured_pass`); `quinn_transport` is also measured in `2026-06-03-graviton4-suite-rep1.json`. | They are not H3 rows and are outside H3 superiority gates. |
| Runtime dependency boundary | Native H3/QUIC runtime is not shelled out to `quiche` or `h3-quinn`. | Runtime lives under `src/transport/h3/`; third-party H3 clients live in `benches/native_h3_vs_rust_clients/`. | BoringSSL remains the TLS backend; TLS fingerprinting is constrained by its ClientHello machinery where noted below. |

## Active Gaps

No active native H3 P0/P1/P2 gaps remain in this ledger.

## Closed Gaps / Regression Guards

Keep these under regression coverage; do not relist them as active gaps.

| Area | Closed state |
|---|---|
| Same-fixture H3 GET superiority | The GET-only ledger repeat gate passed twice consecutively at `ba356d7`: Warpsock worst rep ahead of every comparator per-metric best rep on all six metrics (TTFB p50/p95, ledger throughput, ledger tail p50/p95). |
| RFC 9220 steadystate tunnel tail | Warpsock holds the lower p95 round-trip tail on echo, close/FIN, and mixed under symmetric warm-vs-warm measurement; the prior echo/close p95 losses were warm-vs-cold asymmetry plus the since-fixed inline DPLPMTUD probe spike (`5e0d429`). |
| Out-of-order stream reassembly | Pending-segment buffering with final-size tracking (RFC 9000 Section 2.2) replaced the in-order-only guard that froze GETs under reordering; netem repro went 0/8 to 8/8 (`2406de6`, `docs/benchmarks/native-h3-vs-rust-clients/2026-06-09-rtt-reorder-reassembly-fix/`). |
| `tokio_quiche` body/FIN blocker | Latest persisted full same-fixture proofs emit no fixture events; the previous body timeout is not reproducing in current artifacts. |
| Fixture event classification | Fixture events serialize stable `category` and `fatal` fields; ignored post-application short-header packet-open noise is suppressed from logs and artifacts, while non-ignored packet errors remain serialized with `category` and `fatal`; current release artifacts have zero events. |
| QUIC connection IDs | Required server transport parameters include original-destination, initial-source, and retry-source CIDs; server/client 1-RTT routing uses the expected CIDs. |
| Retry and Version Negotiation | Retry integrity, Retry-driven Initial restart, VN-driven version selection/restart, loop guards, and no-overlap errors are implemented. |
| PATH_CHALLENGE primitives | Client and server packetization, matching PATH_RESPONSE validation, and peer-address-bound migration validation are implemented. |
| Post-handshake NEW_CONNECTION_ID | `NativeQuicServerHandshake::build_server_new_connection_id_packet` can issue migration CIDs after application keys, and the local same-fixture server advertises/registers a migration CID after HandshakeDone. |
| Server-side path migration lifecycle | Server CID inventory (local + peer), multi-CID inbound decrypt, padded PATH_CHALLENGE/PATH_RESPONSE, disabled-migration `CONNECTION_MIGRATION` close, client post-handshake NEW_CONNECTION_ID issuance, mock-server `QuicServerPathRuntime` promotion, and driver `QuicPathSet` validation sync are implemented with regression coverage in `tests/h3_native_path_migration.rs`, `tests/h3_native_handshake.rs`, and `src/transport/h3/path.rs::tests`. |
| Driver anti-amplification gating | Native H3 driver records received bytes per path, promotes validated migrated paths, and routes outbound sends through RFC9000 Section 8.1 budget checks for unvalidated paths. |
| RFC9002 recovery/PTO core | Per-space RTT/PTO/loss state, congestion response, CRYPTO PTO retransmission, app-space PTO, and mock/same-fixture server wake paths are implemented. |
| Recovery soak/backoff validation | Repeated PTO backoff/reset, packet/time-threshold loss, persistent congestion collapse, early timer-poll no-op behavior, Initial/Handshake CRYPTO PTO retransmission, and client/server app-space STREAM retransmission are covered by recovery and handshake regression tests. |
| Browser ACK parity | Chrome H3 uses ACK decimation threshold 10 with `max_ack_delay_ms = 25`; Firefox H3 uses Neqo-style ACK-after-2 behavior with `max_ack_delay_ms = 20`. Client/server/mock/same-fixture ACK timer paths consume the fingerprint values. The 2026-06-09 GET gates run at the shipping threshold-10 cadence. |
| Close drain | Client, mock-server, and same-fixture server retain/replay protected `CONNECTION_CLOSE` packets during bounded drain windows and suppress non-close sends after draining. |
| Key update | 1-RTT key update has traffic-secret/key-phase rotation, previous-key retention, and local-update ACK gating. |
| ACK_ECN and ECN marking | ACK_ECN encode/decode, counter validation, CE growth tracking, congestion response, socket receive ECN reporting, and fingerprint-controlled outbound ECN marking are implemented. |
| PMTU probing | Native H3 has probe policy, PING+PADDING probes, ACK-only promotion, loss-driven search-ceiling reduction, and tunnel-aware probe deferral (`PMTU_TUNNEL_IDLE_GAP`) that keeps probes off the interactive recv-to-send turn. |
| ACK timer/decimation | Pending ACKs flush on `max_ack_delay_ms`; idle handling treats delayed ACKs as driver work; direct-GET epoch boundary ACKs are sealed at their threshold crossings and dispatched on the next flush boundary with identical wire cadence. |
| TLS/H3 capture presets | Certificate compression, deterministic-vs-browser-permuted extension policy, `TlsFingerprint::extension_order`, session-ticket capture/replay, `NativeH3SessionCache`, 0-RTT controls, and explicit Chrome/Firefox capture-ordered QUIC transport parameter presets are wired. |
| Raw ordered transport parameters | Caller-supplied and browser preset raw ordered QUIC transport parameter lists encode in order with dynamic CID placeholders and pool-key separation. |
| H3 scheduling/fairness | Request-body/tunnel DATA class rotation, per-stream rotation, adaptive DATA budgets, and origin-fair slow-path dispatch are implemented. |
| Flow control/backpressure | Streaming responses and RFC9220 tunnels release receive credit on public byte consumption; RFC9220 outbound sends use byte permits and release them on transmit. |
| H3/RFC9220 capacity metrics | `Body::h3_capacity()` reports native H3 streaming body buffer pressure; `H3Tunnel::capacity()` reports RFC9220 inbound/outbound byte-budget pressure. |
| Cross-protocol capacity policy | `CapacityPolicy` provides one public builder surface across H1 active connection slots, H2 local stream slots, H2/H3 streaming body queue slots, and H3 RFC9220 inbound/outbound tunnel byte budgets. |
| RFC9220 comparator rows | Warpsock echo/close/mixed rows and low-level `quiche`/`tokio-quiche` echo/close/mixed rows are persisted under the fair steadystate harness. |
| Transport-only adapters | `quinn_transport` and optional `s2n_quic_transport` have measured rows and are explicitly outside H3 superiority gates. |

## Current Proof Artifacts

| Artifact | Purpose | Gate/sample note |
|---|---|---|
| `docs/benchmarks/native-h3-vs-rust-clients/2026-06-09-direct-get-clientpin-clean-gate/` and `-r2/` | Canonical GET-only ledger repeat gate double pass. | rc=0; n=100 plus 10 warmups, 4 fresh-process reps per client per gate; worst-vs-best on all six metrics. |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-06-09-pmtu-probe-tunnel-defer/` | Fair warm-vs-warm steadystate RFC 9220 tunnel result. | Warpsock lower p95 tail on echo, close, mixed (8 reps, n=100); strict full-suite gate still fails on echo p50/throughput parity. |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-06-09-rtt-reorder-reassembly-fix/` | Out-of-order reassembly fix evidence. | netem 200us repro 0/8 to 8/8; RTT0 A/B unchanged. |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-06-03-graviton4-suite-rep1.json` / `-rep2.json` | Most recent combined all-client capture; measured `quinn_transport` row. | Warm-vs-cold H3/tunnel numbers superseded by the 2026-06-09 results. |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-suite-n100.json` | Transport-baseline regression fixture (`quinn_transport` + `s2n_quic_transport` both `measured_pass`). | Guarded by `tests/h3_competitor_benchmark.rs`; its Mac-sourced gate claims are superseded. |

## Current RFC9220 Rows (fair warm-vs-warm steadystate, awsdev Graviton4, n=100)

| Tunnel workload | Warpsock p50 | Warpsock p95 | tokio-quiche p50 | tokio-quiche p95 | Result |
|---|---:|---:|---:|---:|---|
| echo (1 KB single frame) | 32.9 us | 40.3 us | 32.4 us | 51.2 us | p95 win (non-overlapping across 8 reps); p50 and throughput parity |
| client DATA+FIN (close) | 69.7 us | 80.1 us | 75.3 us | 101.9 us | win p50, p95, and throughput |
| slow-consumer mixed | 37.1 us | 42.3 us | 63.6 us | 68.1 us | win p50 and p95 |

`quiche_direct` runs ~3.3-3.4 ms on every tunnel workload, several-fold behind both. Unsupported RFC9220 capability-audit rows remain explicit non-comparators: `h3_quinn_rfc9220_tunnel`, `reqwest_h3_rfc9220_tunnel`, `tokio_tungstenite_rfc9220`, and `reqwest_rfc9220`.

## Next Execution Order

No active native H3 P0/P1/P2 execution items remain in this ledger.

## Validation Commands

Use these to refresh the ledger when code changes:

```bash
jq '"'"'.rows[] | select(.competitor_id|test("transport")) | {id:.competitor_id,status,source}'"'"' \
  docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-suite-n100.json
```

```bash
env -i HOME="$HOME" USER="$USER" PATH="/usr/local/bin:/usr/bin:/bin:$HOME/.cargo/bin" \
  GET_ONLY_GATE=1 GET_REPEAT_GATE=1 GET_REPEATS=4 SAMPLES=100 WARMUPS=10 \
  WARPSOCK_NATIVE_H3_DIRECT_GET_IO_EPOCH=1 ARCHIVE_NAME=<fresh-dir> ARCHIVE_SLUG=<slug> \
  bash benches/native_h3_vs_rust_clients/scripts/current_rows_awsdev.sh
```
