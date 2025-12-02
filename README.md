# Specter

HTTP client with full TLS/HTTP2 fingerprint control.

## Features

- **HTTP/1.1, HTTP/2** - Full protocol support with automatic ALPN negotiation
- **HTTP/3** - Experimental support via quiche (separate H3Client)
- **TLS Fingerprinting** - Cipher suite, curves, and sigalgs control via BoringSSL
- **HTTP/2 Fingerprinting** - SETTINGS frame configuration (structure in place)
- **Explicit Control** - No automatic redirects, cookies, or headers
- **Connection Pooling** - Pool types for HTTP/2 and HTTP/3 stream multiplexing

## Installation

```toml
[dependencies]
specter = "0.1"
```

## Usage

```rust
use specter::{Client, FingerprintProfile};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), specter::Error> {
    // HTTP/1.1 and HTTP/2 client
    let client = Client::builder()
        .fingerprint(FingerprintProfile::Chrome131)
        .timeout(Duration::from_secs(30))
        .prefer_http2(true)
        .build()?;

    let response = client.get("https://example.com")
        .send()
        .await?;

    println!("Status: {}", response.status());
    println!("Body: {}", response.text()?);

    Ok(())
}
```

### HTTP/3 (Experimental)

```rust
use specter::H3Client;

let h3 = H3Client::new();
let response = h3.send_request(
    "https://cloudflare.com",
    "GET",
    vec![],
    None,
).await?;
```

## Current Limitations

**This crate is experimental and has significant limitations:**

### Fingerprinting Accuracy
- **Outdated Version**: Implements Chrome 131, but Chrome 142 is current (Dec 2025)
- **Extension Randomization**: Chrome randomizes TLS extension order since v110, making static fingerprints detectable
- **Partial Implementation**: Only cipher suites, curves, and signature algorithms are applied. TLS extensions are defined but not applied to connections.
- **No JA4 Support**: Modern detection uses JA4 which handles extension randomization

### Non-Functional Features  
- **HTTP/3 TLS fingerprinting**: quiche doesn't expose BoringSSL configuration
- **HTTP/2 SETTINGS fingerprinting**: hyper doesn't expose h2 settings configuration
- **Connection pooling**: Types exist but are not integrated into clients
- **Firefox/Safari profiles**: Removed (were returning empty configurations)

### Detection Risk
Using this crate against modern anti-bot systems may result in WORSE detection rates than no fingerprinting, because it creates a unique signature (Chrome User-Agent + non-Chrome TLS fingerprint).

### Recommended Use Cases
- Learning about HTTP client implementation
- Internal tools where fingerprinting isn't critical
- Testing and development environments

## License

MIT
