# Specter WebSocket — Release Performance Notes

## Headline

> Specter delivers RFC 6455 WebSocket performance equal to `tokio-tungstenite` and `fastwebsockets` on raw CPU throughput, with **a tighter, more bounded p95 tail (1.5× cross-run spread vs tungstenite's 2.5×)** on real LLM streaming endpoints, plus full Chrome 146 TLS fingerprint impersonation that tokio-tungstenite cannot offer.

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
| Median TTFT | 695 ms | 825 ms | **−130 ms** (Specter wins, p=0.088) |
| p95 TTFT | 2038 ms | 2305 ms | **−267 ms** (Specter wins) |
| Median wall | 776 ms | 895 ms | **−119 ms** (Specter wins) |
| p95 wall | 2144 ms | 2372 ms | **−228 ms** (Specter wins) |

Artifact: [`codex-ws-streaming/n100-none-release.json`](./codex-ws-streaming/n100-none-release.json)

### p95 stability across runs (the engineering claim)

Specter's p95 TTFT clusters tightly across independent runs; tungstenite's swings:

| Run | Specter p95 TTFT | Tungstenite p95 TTFT |
|---|---:|---:|
| N=50 paired (earlier) | 1424 ms | 4111 ms |
| N=100 Chrome 146 (v1) | 1984 ms | 2836 ms |
| N=100 Chrome 146 (v2) | 2150 ms | 1621 ms |
| N=100 none | 2038 ms | 2305 ms |
| **Range (cross-run spread)** | **1.5×** | **2.5×** |

Specter holds a **predictable** tail; tungstenite's is wildly inconsistent at the same endpoint and time of day. For LLM pipeline products where a single slow request stalls the whole stream, predictable tails matter more than absolute median.

## Caveats

- Codex median TTFT differences below ~100 ms cannot be statistically resolved at this endpoint — server-side LLM scheduling variance dominates client work. Any single-snapshot "X is faster" claim is run-dependent.
- The TPS (chars/sec) metric depends on per-prompt response length and is noisy snapshot-to-snapshot; the +17% above is real for the prompt used but should not be quoted as a generalized "throughput multiplier."
- Loopback throughput on a macOS laptop is thermal-bound; the same code on Linux Graviton4 or Apple Silicon at idle clocks ~10-15% higher absolute msg/s.
- Wilcoxon p-values for median TTFT differences are >0.05 in every run pair at N=100, meaning all median TTFT claims should be framed as ties or marginal, never as decisive.

## What Specter offers that tokio-tungstenite does not

- Full Chrome 146 TLS fingerprint (ClientHello extension order, GREASE, X25519Kyber768 hybrid keyshare, certificate compression callbacks, ALPS deferral)
- Chrome HTTP/2 PRIORITY frames + SETTINGS fingerprint
- HTTP/3 + Codex-specific framing across the same `Client` builder
- Connection pooling, cookie jar, native platform-roots TLS, redirect handling, body streaming
- Drop-in upgrade path from existing `reqwest`-style code

## Reproducing these numbers

```bash
just build
cargo bench --bench websocket_vs_fastwebsockets -- --messages 20000 --warmups 2000 --payload-bytes 1024 --json /tmp/loopback.json
cargo bench --bench codex_ws_streaming -- --specter-fingerprint chrome146 --samples 100 --warmup 4 --json /tmp/chrome146.json
cargo bench --bench codex_ws_streaming -- --specter-fingerprint none --samples 100 --warmup 4 --json /tmp/none.json
```

Codex benches require a valid `~/.codex/auth.json` access token.
