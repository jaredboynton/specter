# Specter

HTTP client with full TLS/HTTP2 fingerprint control.

## Features

- **HTTP/1.1, HTTP/2, HTTP/3** - Full protocol support with automatic negotiation
- **TLS Fingerprinting** - JA3/JA4 control via BoringSSL
- **HTTP/2 Fingerprinting** - SETTINGS frame control for browser impersonation
- **Explicit Control** - No automatic redirects, cookies, or headers
- **Connection Multiplexing** - Efficient HTTP/2 and HTTP/3 stream reuse

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
    let client = Client::builder()
        .fingerprint(FingerprintProfile::Chrome131)
        .timeout(Duration::from_secs(30))
        .prefer_http3(true)
        .build()?;

    let response = client.get("https://example.com")
        .send()
        .await?;

    println!("Status: {}", response.status());
    println!("Body: {}", response.text()?);

    Ok(())
}
```

## License

MIT
