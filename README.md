# Specter

HTTP client that accurately replicates Chrome's TLS and HTTP/2 behavior, letting you automate browser workflows programmatically.

## What This Is

Specter implements HTTP/1.1, HTTP/2, and HTTP/3 with the same protocol fingerprints as Chrome. It's written in Rust with a custom HTTP/2 implementation built from RFC 9113 (we don't use hyper or the h2 crate). TLS uses BoringSSL - Chrome's actual TLS library. When you make requests with Specter, fingerprinting systems see the same signatures they'd see from Chrome 142. Validated against ScrapFly, Browserleaks, and tls.peet.ws.

```toml
[dependencies]
specter = "0.1"
```

## Usage

```rust
use specter::{Client, FingerprintProfile};

#[tokio::main]
async fn main() -> Result<(), specter::Error> {
    let client = Client::builder()
        .fingerprint(FingerprintProfile::Chrome142)
        .build()?;

    let response = client.get("https://example.com")
        .send()
        .await?;

    println!("Status: {}", response.status());
    println!("Body: {}", response.text()?);

    Ok(())
}
```

Force a specific HTTP version if needed:

```rust
use specter::HttpVersion;

// HTTP/2 only
client.get(url).version(HttpVersion::Http2).send().await?;

// HTTP/3 with H1/H2 fallback
client.get(url).version(HttpVersion::Http3).send().await?;
```

## Implementation

**HTTP/1.1** - Direct socket implementation, no hyper dependency.

**HTTP/2** - Custom implementation because the h2 crate doesn't expose SETTINGS frame order, GREASE support, or connection preface timing. Fingerprinting systems check all of this. We implemented HTTP/2 from RFC 9113 with fluke-hpack for HPACK compression. This gives us:
- Correct SETTINGS order: `1:65536;2:0;3:1000;4:6291456;5:16384;6:262144`
- GREASE support (`0x0a0a:0` setting)
- Chrome pseudo-header order (m,s,a,p)
- WINDOW_UPDATE: 15663105 (Chrome's connection window)
- All headers properly lowercased per RFC 7540/9113

**HTTP/3** - QUIC transport via quiche with TLS 1.3 fingerprinting.

**TLS** - BoringSSL configured with Chrome 142 cipher suites, curves, and signature algorithms. BoringSSL does its own extension randomization (which matches Chrome's behavior for TLS 1.3).

**Control** - Nothing happens automatically. You manage redirects, cookies, and headers explicitly.

## Verified Against

Tested against production fingerprinting services:
- ScrapFly (tools.scrapfly.io) - matches Chrome fingerprint
- Browserleaks (tls.browserleaks.com) - TLS fingerprint validation
- tls.peet.ws - HTTP/2 Akamai fingerprint validation
- Cloudflare - HTTP/3 support

Run the validation example to test yourself:

```bash
cargo run --example fingerprint_validation
```

## License

MIT
