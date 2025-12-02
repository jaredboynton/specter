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

- HTTP/3 TLS fingerprinting not yet supported (quiche doesn't expose BoringSSL config)
- HTTP/2 SETTINGS fingerprinting requires lower-level h2 access
- Connection pooling types exist but not yet integrated into clients
- Only Chrome131 has full fingerprint implementation

## License

MIT
