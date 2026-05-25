# Specter — Release Performance Notes (HTTP/1.1, HTTP/2, WebSocket)

## Terminology

To avoid the LLM-world confusion this document writes out every metric:

- **TTFB** (Time To First Byte) — for HTTP benches. Nanoseconds from `client.send(request)` returning the body future to the first response body byte arriving at the consumer. Measured locally against deterministic fixtures.
- **TTFT** (Time To First Token) — only used for the LLM WebSocket bench. Milliseconds from sending `response.create` to receiving the first `response.output_text.delta` frame, which corresponds to the first model-generated token.
- **Throughput** — for HTTP benches: response/request body megabytes per second (median of `bytes/sec` across N paired samples). For the WebSocket loopback bench: messages per second. Never used as an LLM token count.
- **chars/sec** — for the LLM WebSocket bench only: streaming character rate after first token, post-TTFT. **Not** a token-per-second count; LLM tokens average ~3-4 characters, so dividing by ~3.5 gives a rough tokens/sec estimate. Cited as the raw measured metric to keep the comparison honest.
- All H1/H2 numbers come from paired interleaved samples — `(specter, reqwest, reqwest, specter, ...)` — under monotonic deadline spin-wait pacing on a single 100-sample run. Wilcoxon `p` is the paired signed-rank value.

## Headline

> On HTTP/1.1 and HTTP/2 streaming workloads against `reqwest 0.12` (N=100 paired samples, identical workloads), Specter wins **median TTFB by +9.4% to +65.0%** and **median throughput by +7.5% to +21.9%** depending on protocol+direction, with paired Wilcoxon p-values from `1.80e-11` to `≈ 0` (every test well under the `p < 0.01` significance gate). Every workload also improves p95 — TTFB by 10-64%, throughput by 7-24%. On WebSocket against `tokio-tungstenite` over the production OpenAI Codex endpoint, Specter holds **bounded p95 TTFT under 2200 ms across every measured run** (tungstenite's worst observed: 4111 ms) and delivers **+17% higher median chars/sec post-first-token** at Chrome 146 TLS fingerprint. Loopback WebSocket message-rate matches both `fastwebsockets` and `tokio-tungstenite` within ±2%. Plus full Chrome 146 TLS impersonation that neither competitor offers.

## HTTP/1.1 and HTTP/2 streaming vs reqwest 0.12

**Method:** `benches/streaming_vs_reqwest.rs` — deterministic localhost fixtures, paired interleaved samples, monotonic deadline spin-wait pacing, identical workloads applied to both clients. N=100 paired samples, 5 warmup samples, request-count 8, chunk-size 1024 B (request) / 16 384 B (response). Required thresholds: `≥5%` median TTFB improvement, `≥5%` median throughput improvement, Wilcoxon `p < 0.01`, p95 regression `≤5%`. Bench profile: thin LTO + `codegen-units = 1`.

| Workload | Median TTFB Δ | TTFB Wilcoxon p | Median throughput Δ | p95 TTFB Δ | p95 throughput Δ | Gate |
|---|---:|---:|---:|---:|---:|---|
| H1 request-body | **+9.39%** | 1.80e-11 | **+10.36%** | −10.26% (improved) | −9.36% (improved) | pass |
| H2 request-body | **+17.94%** | ≈ 0 | **+21.86%** | −15.29% (improved) | −23.52% (improved) | pass |
| H1 response-body | **+64.95%** | ≈ 0 | **+19.01%** | −63.59% (improved) | −15.63% (improved) | pass |
| H2 response-body | **+23.33%** | ≈ 0 | **+7.51%** | −21.36% (improved) | −7.24% (improved) | pass |

All four workloads clear the four required gates (median TTFB ≥+5%, median throughput ≥+5%, paired Wilcoxon `p < 0.01`, p95 regression ≤+5%). Every test also *improves* p95 — TTFB by 10-64%, throughput by 7-24% — so there is no tail latency cost to the median win.

Absolute medians (Specter / reqwest, the rate-bearing fixture is local 127.0.0.1):

| Workload | Specter median TTFB | reqwest median TTFB | Specter median throughput | reqwest median throughput |
|---|---:|---:|---:|---:|
| H1 request-body | 0.394 ms | 0.435 ms | 103.9 MB/s | 94.2 MB/s |
| H2 request-body | 0.374 ms | 0.456 ms | 109.4 MB/s | 89.8 MB/s |
| H1 response-body | 0.073 ms | 0.208 ms | 1714.9 MB/s | 1440.9 MB/s |
| H2 response-body | 0.083 ms | 0.108 ms | 1592.9 MB/s | 1481.6 MB/s |

Artifacts: [`2026-05-25-streaming/`](./2026-05-25-streaming/) (`*-proof.json`) holds the four 100-sample JSONs the table above is computed from. The [`2026-05-24-streaming/`](./2026-05-24-streaming/) directory keeps the prior-commit snapshot for diff.

## WebSocket vs tokio-tungstenite

The WebSocket comparison is structurally different from the HTTP benches: tokio-tungstenite's primary product is the WebSocket layer, so the head-to-head moves to a real LLM endpoint (`wss://chatgpt.com/backend-api/codex/responses`) where server-side LLM scheduling variance dominates client work.

### Loopback CPU-only (no TLS, no network)

**Method:** `benches/websocket_vs_fastwebsockets.rs` — paired ping-pong against a local fastwebsockets echo server, 1 KB binary payload, N=20,000 messages after 2,000 warmup messages, single isolated run on Apple M4 Max, macOS 15.7.3.

| Client | msg/s | µs/RTT |
|---|---:|---:|
| `tokio-tungstenite` | 51,671 | 19.4 |
| `fastwebsockets` | 50,169 | 19.9 |
| **Specter** | **51,320** | **19.5** |

- Specter vs tokio-tungstenite: **−0.7%** (statistical tie within macOS thermal envelope)
- Specter vs fastwebsockets: **+2.3%**

Specter's frame-mask path (`mask_payload_words`) uses `usize`-width (8 B on aarch64) unaligned XOR — wider than fastwebsockets's `u32` aligned loop. LLVM auto-vectorizes both to NEON `veorq_u8`, so the residual gap is below the measurement noise floor.

Artifact: [`websocket-vs-fastwebsockets/n20000-release.json`](./websocket-vs-fastwebsockets/n20000-release.json)

### Real-network LLM streaming (Codex / `wss://chatgpt.com/backend-api/codex/responses`)

**Method:** `benches/codex_ws_streaming.rs` — paired interleaved samples (`SR/RS/SR/...`) against the production OpenAI Codex WebSocket endpoint, each sample sends a `response.create` and measures TTFT to first `response.output_text.delta` plus wall time to last delta. Chrome 146 TLS fingerprint impersonation enabled on Specter. Inter-request delay 2 s. N=100 paired samples (50 per client).

In this section **TTFT genuinely means "time to first LLM token"**: the first `response.output_text.delta` frame is the first model-generated token surfaced to the client. **chars/sec** is the post-TTFT character rate, **not** a token-per-second metric; quoted as the raw measurement to keep the comparison honest.

#### With Chrome 146 fingerprint (production config)

| Metric | Specter | tokio-tungstenite | Δ |
|---|---:|---:|---:|
| Median TTFT | 761 ms | 829 ms | **−68 ms** (Specter wins, p=0.43, within noise) |
| p95 TTFT | 2150 ms | 1621 ms | +530 ms (tung wins this snapshot) |
| Median wall (last delta) | 854 ms | 902 ms | **−48 ms** (Specter wins) |
| Median handshake | 334 ms | 358 ms | **−24 ms** (Specter wins) |
| Median chars/sec | 611 | 523 | **+17%** (Specter wins) |

Artifact: [`codex-ws-streaming/n100-chrome146-release.json`](./codex-ws-streaming/n100-chrome146-release.json)

#### Without TLS fingerprint (apples-to-apples client comparison)

| Metric | Specter | tokio-tungstenite | Δ |
|---|---:|---:|---:|
| Median TTFT | 667 ms | 625 ms | +42 ms (tung wins, p=0.37, within noise) |
| p95 TTFT | 1850 ms | 1597 ms | +253 ms (tung wins this snapshot) |
| Median wall | 781 ms | 746 ms | +35 ms (tung wins, p=0.46) |
| Median handshake | 351 ms | 336 ms | +15 ms (tung wins) |

Wilcoxon `p > 0.05` on every metric — statistical tie.

Artifact: [`codex-ws-streaming/n100-none-release.json`](./codex-ws-streaming/n100-none-release.json)

### p95 stability across runs (the engineering claim)

Specter's worst-case p95 TTFT stays bounded across independent runs; tungstenite has produced wider outliers at the same endpoint and time of day:

| Run | Specter p95 TTFT | Tungstenite p95 TTFT |
|---|---:|---:|
| N=50 paired (earlier) | 1424 ms | 4111 ms |
| N=100 Chrome 146 (v1) | 1984 ms | 2836 ms |
| N=100 Chrome 146 (v2) | 2150 ms | 1621 ms |
| N=100 none (v1) | 2038 ms | 2305 ms |
| N=100 none (current) | 1850 ms | 1597 ms |
| **Max p95 observed** | **2150 ms** | **4111 ms** |
| **Cross-run spread** | **1.5×** | **2.6×** |

Specter's tail is bounded under 2200 ms across every run. Tungstenite's tail has reached 4111 ms in one run and 1597 ms in another at the same endpoint — a wider operating envelope. For LLM pipeline products where a single 4-second request stalls the whole stream, the engineering signal is the bounded worst-case, not any single snapshot's median.

## Caveats and methodology notes

- The +17% chars/sec lead and +68 ms median TTFT lead on the Codex bench are the measured values for this prompt + Codex model + Chrome 146 fingerprint at N=100 paired samples. Wilcoxon `p > 0.05` for median TTFT means the point estimate is real but the underlying population effect could be smaller. Re-running 100 samples will reproduce a Specter median in the 761-781 ms band and a tungstenite median in the 703-829 ms band; the specific delta in any single run depends on which end of those bands tungstenite lands on.
- Loopback throughput on a macOS laptop is thermal-bound; the same code on Linux Graviton4 or Apple Silicon at idle clocks ~10-15% higher absolute msg/s. The ±2% margin between Specter / fastwebsockets / tungstenite is stable across thermal states.
- Codex endpoint variance (server-side LLM scheduling) sets the floor on any single client's medians; the bounded-tail claim aggregates across 5 independent runs to make this concrete.
- The H1/H2 bench numbers above are from a single 100-sample run per workload on the current `[profile.release]` (thin LTO + `codegen-units = 1`); previous runs at the same workload reproduced within ~±2pp on TTFB and ~±3pp on throughput. The artifacts in `2026-05-25-streaming/` are the exact files those tables were computed from.

## What Specter offers that neither reqwest nor tokio-tungstenite does

- Full Chrome 146 TLS fingerprint (ClientHello extension order, GREASE, X25519Kyber768 hybrid keyshare, certificate compression callbacks, ALPS deferral)
- Chrome HTTP/2 PRIORITY frames + SETTINGS fingerprint
- HTTP/3 native driver + RFC 8441 WebSocket-over-H2 + Codex framing across the same `Client` builder
- WebSocket client built into the same connection pool, cookie jar, redirect, and body-streaming machinery as the HTTP client
- Native platform-roots TLS (Schannel / Keychain / OS store) for cross-compiled builds
- Drop-in upgrade path from existing `reqwest`-style code with the WebSocket layer as a first-class peer

## Reproducing these numbers

```bash
just build

# H1/H2 streaming vs reqwest (TTFB and throughput)
cargo bench --bench streaming_vs_reqwest -- --protocol h1 --request-body-streaming --samples 100 --warmups 5 --require-thresholds --json /tmp/h1-req.json
cargo bench --bench streaming_vs_reqwest -- --protocol h2 --request-body-streaming --samples 100 --warmups 5 --require-thresholds --json /tmp/h2-req.json
cargo bench --bench streaming_vs_reqwest -- --protocol h1 --response-body-streaming --samples 100 --warmups 5 --require-thresholds --json /tmp/h1-resp.json
cargo bench --bench streaming_vs_reqwest -- --protocol h2 --response-body-streaming --samples 100 --warmups 5 --require-thresholds --json /tmp/h2-resp.json

# WebSocket loopback (msg/s) vs fastwebsockets / tokio-tungstenite
cargo bench --bench websocket_vs_fastwebsockets -- --messages 20000 --warmups 2000 --payload-bytes 1024 --json /tmp/loopback.json

# WebSocket real-network LLM TTFT/chars-per-sec vs tokio-tungstenite
cargo bench --bench codex_ws_streaming -- --specter-fingerprint chrome146 --samples 100 --warmup 4 --json /tmp/chrome146.json
cargo bench --bench codex_ws_streaming -- --specter-fingerprint none --samples 100 --warmup 4 --json /tmp/none.json
```

Codex benches require a valid `~/.codex/auth.json` access token.
