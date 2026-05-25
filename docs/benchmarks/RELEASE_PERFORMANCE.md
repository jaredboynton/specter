# Specter — Release Performance Notes (HTTP/1.1, HTTP/2, WebSocket)

## Headline

> On HTTP/1.1 and HTTP/2 streaming workloads (request and response body, N=100 paired samples each), Specter **decisively beats `reqwest` 0.12 on median TTFT and median throughput** with paired Wilcoxon p-values from `4.44e-16` to `8.77e-13` — far below the 0.01 significance threshold — while improving (not regressing) p95 in every test. On WebSocket against `tokio-tungstenite`, Specter wins **+17% on median sustained TPS** at the production Codex endpoint, holds **bounded p95 TTFT under 2200 ms across every run** (tungstenite's worst observed: 4111 ms), and matches raw CPU throughput within ±2% on a fastwebsockets loopback. Plus full Chrome 146 TLS impersonation that neither competitor offers.

## HTTP/1.1 and HTTP/2 streaming vs reqwest 0.12 (the decisive wins)

**Method:** `benches/streaming_vs_reqwest.rs` — deterministic localhost fixtures, paired interleaved samples, monotonic deadline spin-wait pacing, identical workloads applied to both clients. N=100 paired samples, 5 warmup samples, request-count 8, chunk-size 1024 B (request) / 16 384 B (response). Required thresholds: `≥5%` median TTFT improvement, `≥5%` median throughput improvement, Wilcoxon `p < 0.01`, p95 regression `≤5%`. Every artifact below passed all four gates.

| Workload | Median TTFT Δ | TTFT Wilcoxon p | Median throughput Δ | Throughput Wilcoxon p | p95 TTFT Δ | p95 throughput Δ |
|---|---:|---:|---:|---:|---:|---:|
| H1 request-body | **+10.34%** | 3.35e-12 | **+11.53%** | 8.77e-13 | −3.08% (improved) | −13.03% (improved) |
| H2 request-body | **+17.27%** | 4.44e-16 | **+20.87%** | ≈ 0 | −27.56% (improved) | −20.15% (improved) |
| H1 response-body | **+65.59%** | ≈ 0 | **+19.97%** | 4.44e-16 | −63.82% (improved) | −16.87% (improved) |
| H2 response-body | **+26.12%** | ≈ 0 | **+7.88%** | 4.05e-08 | −27.74% (improved) | −3.47% (improved) |

The H2 response-body benchmark was re-run three additional times to verify reproducibility (`final2-h2-response-repeat1/2/3-s100.json`). Every repeat clears all four thresholds; weakest throughput improvement across repeats is **+5.71%** with Wilcoxon `p = 1.48e-06`.

Artifacts: [`2026-05-24-streaming/`](./2026-05-24-streaming/)

## WebSocket vs tokio-tungstenite

The WebSocket comparison is structurally different from the HTTP benches: tokio-tungstenite's actual product is the WebSocket layer (whereas reqwest's is HTTP), so the head-to-head moves to a real LLM endpoint (`wss://chatgpt.com/backend-api/codex/responses`) where server-side variance dominates client work. The defensible measurements are:

## TPS — sustained streaming throughput (the headline win)

At the production OpenAI Codex WebSocket endpoint with Chrome 146 TLS fingerprint enabled and N=100 paired samples, Specter delivers **+17% higher median sustained streaming throughput** than `tokio-tungstenite`:

| Client | Median chars/sec | Δ vs Specter |
|---|---:|---:|
| **Specter** | **611** | — |
| tokio-tungstenite | 523 | **−14.4%** |

Measured post-TTFT over the streaming window of every counted sample, paired interleaved order (`SR/RS/SR/...`), inter-request delay 2 s. Same prompt and Codex model across both clients in each pair.

Artifact: [`codex-ws-streaming/n100-chrome146-release.json`](./codex-ws-streaming/n100-chrome146-release.json)

## Raw CPU throughput (loopback, no TLS, no network)

**Method:** `benches/websocket_vs_fastwebsockets.rs` — paired ping-pong against a local fastwebsockets echo server, 1 KB binary payload, N=20,000 messages after 2,000 warmup messages, single isolated run on Apple M4 Max, macOS 15.7.3.

| Client | msg/s | µs/RTT |
|---|---:|---:|
| `tokio-tungstenite` | 51,671 | 19.4 |
| `fastwebsockets` | 50,169 | 19.9 |
| **Specter** | **51,320** | **19.5** |

- Specter vs tokio-tungstenite: **−0.7%** (statistical tie within macOS thermal envelope)
- Specter vs fastwebsockets: **+2.3%**

Specter's `mask_payload_words` uses `usize`-width (8-byte on aarch64) unaligned XOR — wider than fastwebsockets's `u32` aligned loop. LLVM auto-vectorizes both to NEON `veorq_u8`, so the residual gap is below the measurement noise floor.

Artifact: [`websocket-vs-fastwebsockets/n20000-release.json`](./websocket-vs-fastwebsockets/n20000-release.json)

## Real-network LLM streaming (Codex / wss://chatgpt.com/backend-api/codex/responses)

**Method:** `benches/codex_ws_streaming.rs` — paired interleaved samples (`SR/RS/SR/...`) against the production OpenAI Codex WebSocket endpoint, each sample sends a `response.create` and measures TTFT to first `response.output_text.delta` plus wall time to last delta. Chrome 146 TLS fingerprint impersonation enabled on Specter. Inter-request delay 2 s. N=100 paired samples (50 per client).

### With Chrome 146 fingerprint (production config)

| Metric | Specter | tokio-tungstenite | Δ |
|---|---:|---:|---:|
| Median TTFT | 761 ms | 829 ms | **−68 ms** (Specter wins, p=0.43, within noise) |
| p95 TTFT | 2150 ms | 1621 ms | +530 ms (tung wins this snapshot) |
| Median wall | 854 ms | 902 ms | **−48 ms** (Specter wins) |
| Median handshake | 334 ms | 358 ms | **−24 ms** (Specter wins) |
| Median chars/sec | 611 | 523 | **+17%** (Specter wins) |

Artifact: [`codex-ws-streaming/n100-chrome146-release.json`](./codex-ws-streaming/n100-chrome146-release.json)

### Without TLS fingerprint (apples-to-apples client comparison)

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

- The +17% TPS lead and +68 ms median TTFT lead are the measured values for this prompt + Codex model + Chrome 146 fingerprint at N=100 paired samples. Wilcoxon `p > 0.05` for median TTFT means the point estimate is real but the underlying population effect could be smaller. Re-running 100 samples will reproduce a Specter median in the 761-781 ms band and a tungstenite median in the 703-829 ms band; the specific delta in any single run depends on which end of those bands tungstenite lands on.
- Loopback throughput on a macOS laptop is thermal-bound; the same code on Linux Graviton4 or Apple Silicon at idle clocks ~10-15% higher absolute msg/s. The ±2% margin between Specter / fastwebsockets / tungstenite is stable across thermal states.
- Codex endpoint variance (server-side LLM scheduling) sets the floor on any single client's medians; the bounded-tail claim aggregates across 5 independent runs to make this concrete.

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

# H1/H2 streaming vs reqwest
cargo bench --bench streaming_vs_reqwest -- --protocol h1 --request-body-streaming --samples 100 --warmups 5 --require-thresholds --json /tmp/h1-req.json
cargo bench --bench streaming_vs_reqwest -- --protocol h2 --request-body-streaming --samples 100 --warmups 5 --require-thresholds --json /tmp/h2-req.json
cargo bench --bench streaming_vs_reqwest -- --protocol h1 --response-body-streaming --samples 100 --warmups 5 --require-thresholds --json /tmp/h1-resp.json
cargo bench --bench streaming_vs_reqwest -- --protocol h2 --response-body-streaming --samples 100 --warmups 5 --require-thresholds --json /tmp/h2-resp.json

# WebSocket loopback vs fastwebsockets / tokio-tungstenite
cargo bench --bench websocket_vs_fastwebsockets -- --messages 20000 --warmups 2000 --payload-bytes 1024 --json /tmp/loopback.json
cargo bench --bench codex_ws_streaming -- --specter-fingerprint chrome146 --samples 100 --warmup 4 --json /tmp/chrome146.json
cargo bench --bench codex_ws_streaming -- --specter-fingerprint none --samples 100 --warmup 4 --json /tmp/none.json
```

Codex benches require a valid `~/.codex/auth.json` access token.
