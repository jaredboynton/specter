# Specter

Rust HTTP client with Chrome-accurate fingerprints across TLS, HTTP/1.1, HTTP/2, HTTP/3, and WebSockets - automation that looks like a real browser on the wire.

## What This Is

Specter implements HTTP/1.1, HTTP/2, and HTTP/3 with the same protocol fingerprints as Chrome. It's written in Rust with a custom HTTP/2 implementation built from RFC 9113 (we don't use hyper or the h2 crate). TLS uses BoringSSL - Chrome's actual TLS library. When you make requests with Specter, fingerprinting systems see the same signatures they'd see from a real Chrome browser. Validated against ScrapFly, Browserleaks, and tls.peet.ws.

Implemented Chrome fingerprints: **142, 143, 144, 145, 146, 147, 148**. Firefox 133 also supported.
See [`docs/fingerprints/chrome-142-148.md`](docs/fingerprints/chrome-142-148.md) for the Chromium UA-CH algorithm and Chrome Releases version evidence used by these profiles.

```toml
[dependencies]
specter = "3.2"
```

### Certified Chrome profiles

| Profile | Reduced UA milestone | macOS full version used for UA-CH |
| --- | --- | --- |
| `FingerprintProfile::Chrome142` | `Chrome/142.0.0.0` | `142.0.7444.176` |
| `FingerprintProfile::Chrome143` | `Chrome/143.0.0.0` | `143.0.7499.193` |
| `FingerprintProfile::Chrome144` | `Chrome/144.0.0.0` | `144.0.7559.133` |
| `FingerprintProfile::Chrome145` | `Chrome/145.0.0.0` | `145.0.7632.117` |
| `FingerprintProfile::Chrome146` | `Chrome/146.0.0.0` | `146.0.7680.165` |
| `FingerprintProfile::Chrome147` | `Chrome/147.0.0.0` | `147.0.7727.138` |
| `FingerprintProfile::Chrome148` | `Chrome/148.0.0.0` | `148.0.7778.179` |

`Chrome148` is the latest implemented profile. All Chrome 142-148 profiles share the Chrome TLS, HTTP/2, and HTTP/3 transport fingerprints; the User-Agent and UA-CH headers vary by milestone.

## Usage

### Basic request

```rust
use specter::{Client, FingerprintProfile};

#[tokio::main]
async fn main() -> Result<(), specter::Error> {
    let client = Client::builder()
        .fingerprint(FingerprintProfile::Chrome148)
        .build()?;

    let response = client.get("https://example.com")
        .send()
        .await?;

    println!("Status: {}", response.status());
    println!("Body: {}", response.text()?);

    Ok(())
}
```

### Force a specific HTTP version

```rust
use specter::HttpVersion;

// HTTP/2 only
client.get(url).version(HttpVersion::Http2).send().await?;

// HTTP/3 with H1/H2 fallback
client.get(url).version(HttpVersion::Http3).send().await?;
```

### Configure the client builder

```rust
use specter::{Client, FingerprintProfile};
use specter::fingerprint::http2::Http2Settings;
use specter::transport::h2::PseudoHeaderOrder;
use std::time::Duration;

let client = Client::builder()
    .fingerprint(FingerprintProfile::Chrome148)
    .prefer_http2(true)          // advertise h2 first and reuse pooled connections
    .timeout(Duration::from_secs(30))
    .http2_settings(Http2Settings::default())
    .pseudo_order(PseudoHeaderOrder::Chrome)
    .h3_upgrade(true)            // cache Alt-Svc upgrades
    .build()?;
```

- `fingerprint(FingerprintProfile::Chrome148)` selects the TLS, HTTP/2, HTTP/3, User-Agent, and UA-CH fingerprints for the implemented Chrome 148 milestone. Other versions available: `Chrome142` through `Chrome147`.
- `prefer_http2(true)` keeps HTTP/1.1 available through ALPN but defaults to pooled HTTP/2.
- `timeout(...)` adds a global request timeout enforced across all transports.
- `http2_settings(...)` / `pseudo_order(...)` let you override SETTINGS frames and pseudo header ordering when you need to mimic a different browser or experiment with fingerprints.
- `h3_upgrade(false)` disables Alt-Svc based HTTP/3 upgrades if you want deterministic TCP-only behavior.

### Redirects, retries, and cookies stay under your control

Specter never follows redirects or stores cookies automatically by default. That is intentional so you can replay the exact browser flow the target expects. You can opt in:

```rust
use specter::RedirectPolicy;

let client = Client::builder()
    .redirect_policy(RedirectPolicy::Limited(10))
    .cookie_store(true)
    .build()?;
```

Use `CookieJar` plus the header helpers to implement whatever policy you need:

```rust
use specter::{Client, CookieJar, FingerprintProfile, HttpVersion, Result};
use specter::headers::{chrome_148_headers, with_cookies};
use url::Url;

async fn fetch_with_redirects() -> Result<()> {
    let client = Client::builder()
        .fingerprint(FingerprintProfile::Chrome148)
        .prefer_http2(true)
        .build()?;

    let mut jar = CookieJar::new();
    let mut current = Url::parse("https://example.com/login").expect("valid URL");

    for _ in 0..5 {
        let headers = with_cookies(chrome_148_headers(), current.as_str(), &jar);

        let response = client.get(current.as_str())
            .headers(headers)
            .version(HttpVersion::Auto)
            .send()
            .await?;

        jar.store_from_headers(response.headers(), current.as_str());

        if response.is_redirect() {
            if let Some(location) = response.redirect_url() {
                current = current.join(location).expect("relative redirect");
                continue;
            }
        }

        println!("Reached {} with status {}", current, response.status());
        println!("Body: {}", response.text()?);
        break;
    }

    Ok(())
}
```

Use `response.is_redirect()`/`response.redirect_url()` to drive your redirect engine, and `response.url()` if you need to report the final hop back to upstream logic.

### Persist cookies between runs

`CookieJar` understands the standard Netscape cookie format so you can import/export Chrome cookies or maintain your own store:

```rust
let mut jar = CookieJar::new();
jar.load_from_file("cookies.txt").await?;
// ... run requests and call jar.store_from_headers(...)
jar.save_to_file("cookies.txt").await?;
```

### Header presets & origin helpers

`specter::headers` ships Chrome 142-148 navigation, AJAX, and form presets plus helpers such as `with_origin`, `with_referer`, `with_cookies`, and `headers_to_owned`. Start from those presets, then add per-request headers so you never accidentally send forbidden connection-specific headers on HTTP/2/3.

### Response helpers

`Response::decoded_body()`, `Response::text()`, and `Response::json()` transparently decompress gzip/deflate/br/zstd payloads (including chained encodings) before decoding, which matches modern browser behavior.

### WebSockets

Specter supports RFC 6455 WebSockets over HTTP/1.1 Upgrade:

```rust
use specter::{Client, FingerprintProfile, Message};

let mut ws = Client::builder()
    .fingerprint(FingerprintProfile::Chrome148)
    .cookie_store(true)
    .build()?
    .websocket("wss://example.com/socket")
    .subprotocol("chat.v2")
    .connect()
    .await?;

ws.send_text("hello").await?;

while let Some(message) = ws.next().await? {
    match message {
        Message::Text(text) => println!("{text}"),
        Message::Binary(bytes) => println!("{} bytes", bytes.len()),
        _ => {}
    }
}
```

For `wss://`, the RFC 6455 path advertises HTTP/1.1 only via ALPN so the opening handshake stays an HTTP/1.1 Upgrade. Cookie lookup and `Set-Cookie` storage use the equivalent `http://` or `https://` URL, so existing `CookieJar` policy applies to WebSocket handshakes.

Node and Python bindings expose the same RFC 6455 API shape through `client.websocket(...)`, with RFC 6455 messages represented as typed text, binary, ping, pong, and close objects.

Specter also exposes RFC 8441 Extended CONNECT for WebSocket-over-HTTP/2 when the peer advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`:

```rust
use bytes::Bytes;

let mut tunnel = client
    .websocket_h2("wss://example.com/socket")
    .header("origin", "https://example.com")
    .open()
    .await?;

tunnel.send_bytes(Bytes::from_static(b"raw websocket bytes"), false).await?;
```

Node and Python bindings expose RFC 8441 separately as `client.websocketH2(...)` and `client.websocket_h2(...)` raw byte tunnels so framed WebSocket behavior is not mixed with Extended CONNECT streams.

The RFC 8441 API is a byte tunnel. Use it when you need H2 Extended CONNECT semantics directly; use `client.websocket(...)` for the full RFC 6455 frame/message client.

## Performance

Specter ships deterministic localhost streaming benchmarks against `reqwest 0.12`. Across H1 and H2 request- and response-body streaming, Specter beats reqwest on both TTFT and throughput with Wilcoxon p-values well below 0.01. From the persisted 2026-05-24 proof artifacts:

| Workload | Protocol | TTFT Improvement | Throughput Improvement | Throughput p-value | Artifact |
| --- | --- | ---: | ---: | ---: | --- |
| Response-body streaming | H1 | +65.59% | +19.97% | 4.44e-16 | [`final2-h1-response-s100.json`](docs/benchmarks/2026-05-24-streaming/final2-h1-response-s100.json) |
| Response-body streaming | H2 | +26.12% | +7.88% | 4.05e-8 | [`final2-h2-response-s100.json`](docs/benchmarks/2026-05-24-streaming/final2-h2-response-s100.json) |
| Request-body streaming | H1 | +10.34% | +11.53% | 8.77e-13 | [`final2-h1-request-s100.json`](docs/benchmarks/2026-05-24-streaming/final2-h1-request-s100.json) |
| Request-body streaming | H2 | +17.27% | +20.87% | 0 | [`final2-h2-request-s100.json`](docs/benchmarks/2026-05-24-streaming/final2-h2-request-s100.json) |

CI gates require at least 5% median TTFT and throughput improvement, p<0.01, p95 throughput regression at most 5%, and RFC 8441/WebSocket coexistence preserved; the measured numbers above clear those gates by wide margins. Published request artifacts have zero denominator-floor clamps, zero client-write denominator-floor clamps, and zero upload-complete fallbacks. H2 response streaming was repeated three additional times after the final hot-path fix; the weakest repeat still shows +5.71% throughput with p=1.48e-6.

The request-body benchmark uses a fixed `5 x 1024B` body schedule, `2ms` inter-chunk pacing, and an 8-request workload, measured against the fixture upload-complete timestamp rather than response completion.

See [`docs/benchmarks/2026-05-24-streaming/`](docs/benchmarks/2026-05-24-streaming/) for the summary, raw JSON artifacts, exact commands, and RFC 8441 coexistence proof. These are deterministic local benchmark results, not a claim that every network or workload is faster.

## Implementation

**HTTP/1.1** - Direct socket implementation, no hyper dependency.

**HTTP/2** - Custom implementation because the h2 crate doesn't expose SETTINGS frame order, GREASE support, or connection preface timing. Fingerprinting systems check all of this. We implemented HTTP/2 from RFC 9113 with fluke-hpack for HPACK compression. This gives us:
- Correct SETTINGS order: `1:65536;2:0;3:1000;4:6291456;5:16384;6:262144`
- GREASE support (`0x0a0a:0` setting)
- Chrome pseudo-header order (m,s,a,p)
- WINDOW_UPDATE: 15663105 (Chrome's connection window)
- All headers properly lowercased per RFC 7540/9113
- True multiplexing (concurrent requests on single connection, respecting `MAX_CONCURRENT_STREAMS`)

**HTTP/3** - QUIC transport via quiche with TLS 1.3 fingerprinting.

**WebSockets** - RFC 6455 client over HTTP/1.1 Upgrade, plus RFC 8441 Extended CONNECT tunnels over HTTP/2. Compression extensions are intentionally not negotiated.

**TLS** - BoringSSL configured with Chrome cipher suites, curves, and signature algorithms. The TLS configuration is identical across Chrome 142-148. BoringSSL does its own extension randomization (which matches Chrome's behavior for TLS 1.3).

**Control** - Nothing happens automatically. You manage redirects, cookies, headers, and retries explicitly (see the examples above for recommended patterns).

## Testing & Validation

Specter is validated against production fingerprinting services:
- ScrapFly (tools.scrapfly.io) - matches Chrome fingerprint
- Browserleaks (tls.browserleaks.com) - TLS fingerprint validation
- tls.peet.ws - HTTP/2 Akamai fingerprint validation
- Cloudflare - HTTP/3 support

Local/CI checks:

- `cargo test -p specter` exercises the cookie jar, header filtering, and transport layers.
- `cargo run --example fingerprint_validation` hits ScrapFly, BrowserLeaks, tls.peet.ws, and Cloudflare to confirm TLS/HTTP/2/HTTP/3 fingerprints.
- `cargo run --example protocol_test -- --verbose` walks through HTTP/1.1 preference, HTTP/2 pooling, HTTP/3 only, and connection header filtering. Pass `--target example.com` to test a custom origin.
- `cargo clippy -p specter -- -D warnings` stays clean to make CI fail-fast on regressions.

## Development

### Pre-commit Hooks

This project uses [pre-commit](https://pre-commit.com/) to automatically format code and run clippy before commits. Install it once:

```bash
# Install pre-commit (if not installed)
brew install pre-commit  # or: pip install pre-commit

# Install hooks in this repo
pre-commit install
```

After installation, `cargo fmt` and `cargo clippy` will run automatically on each commit. To run manually:

```bash
pre-commit run --all-files
```

## Versioning & Stability

- We follow SemVer. API breaking changes will require a major version bump while fingerprint profile additions remain additive.

## Responsible Use

Specter makes it easy to mimic real Chrome traffic. Please use it responsibly:
- Only target hosts you own or have written permission to test, and obey their terms of service plus local laws.
- Make it clear in your own product documentation that requests are automated; do not use Specter to impersonate real end users.
- Respect robots.txt, rate limits, and authentication boundaries—Specter gives you the tools but you are accountable for policy.
- Keep your own audit logs so you can answer abuse reports quickly.

## License

MIT
