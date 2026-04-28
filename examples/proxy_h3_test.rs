//! HTTP/3 (QUIC) test through SOCKS5 proxy via UDP ASSOCIATE.
//!
//! Usage:
//!   # Direct H3:
//!   cargo run --example proxy_h3_test
//!
//!   # H3 through SOCKS5:
//!   cargo run --example proxy_h3_test -- --socks5 host:port --user USER --pass PASS

use specter::headers::chrome_146_headers;
use specter::{Client, FingerprintProfile, HttpVersion, ProxyConfig};

#[tokio::main]
async fn main() -> Result<(), specter::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("specter=debug".parse().unwrap()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let proxy = parse_proxy(&args);

    let mut builder = Client::builder()
        .fingerprint(FingerprintProfile::Chrome146)
        .with_platform_roots(true)
        .h3_upgrade(true);

    if let Some(ref p) = proxy {
        println!("[*] Proxy: {}", p.proxy_key());
        builder = builder.proxy(p.clone());
    } else {
        println!("[*] Direct (no proxy)");
    }

    let client = builder.build()?;
    let headers = chrome_146_headers();

    // Test 1: HTTP/3 Only (strict — no fallback)
    println!("\n=== Test 1: HTTP/3 Only (strict) ===");
    println!("[>] cloudflare.com via H3 only...");
    match client
        .get("https://cloudflare.com")
        .headers(headers.clone())
        .version(HttpVersion::Http3Only)
        .send()
        .await
    {
        Ok(resp) => {
            println!("    Status: {}", resp.status());
            println!("    HTTP version: {}", resp.http_version());
            let body = resp.text().unwrap_or_default();
            println!("    Body length: {} bytes", body.len());
        }
        Err(e) => println!("    FAILED: {}", e),
    }

    // Test 2: HTTP/3 preferred (with H1/H2 fallback)
    println!("\n=== Test 2: HTTP/3 preferred (fallback to H1/H2) ===");
    println!("[>] cloudflare.com via H3 preferred...");
    match client
        .get("https://cloudflare.com")
        .headers(headers.clone())
        .version(HttpVersion::Http3)
        .send()
        .await
    {
        Ok(resp) => {
            println!("    Status: {}", resp.status());
            println!("    HTTP version: {}", resp.http_version());
            let body = resp.text().unwrap_or_default();
            println!("    Body length: {} bytes", body.len());
        }
        Err(e) => println!("    FAILED: {}", e),
    }

    // Test 3: IP check via H3
    println!("\n=== Test 3: IP check via H3 ===");
    println!("[>] one.one.one.one/cdn-cgi/trace (Cloudflare H3)...");
    match client
        .get("https://one.one.one.one/cdn-cgi/trace")
        .headers(headers.clone())
        .version(HttpVersion::Http3)
        .send()
        .await
    {
        Ok(resp) => {
            println!("    Status: {}", resp.status());
            println!("    HTTP version: {}", resp.http_version());
            let body = resp.text().unwrap_or_default();
            // Parse key fields from trace
            for line in body.lines() {
                if line.starts_with("ip=")
                    || line.starts_with("h=")
                    || line.starts_with("http=")
                    || line.starts_with("tls=")
                    || line.starts_with("loc=")
                    || line.starts_with("colo=")
                {
                    println!("    {}", line);
                }
            }
        }
        Err(e) => println!("    FAILED: {}", e),
    }

    // Test 4: Auto version (check Alt-Svc H3 upgrade)
    println!("\n=== Test 4: Auto version ===");
    println!("[>] httpbin.org/ip via Auto...");
    match client
        .get("https://httpbin.org/ip")
        .headers(headers)
        .version(HttpVersion::Auto)
        .send()
        .await
    {
        Ok(resp) => {
            println!("    Status: {}", resp.status());
            println!("    HTTP version: {}", resp.http_version());
            let body = resp.text().unwrap_or_default();
            println!("    {}", body.trim());
        }
        Err(e) => println!("    FAILED: {}", e),
    }

    Ok(())
}

fn parse_proxy(args: &[String]) -> Option<ProxyConfig> {
    let mut socks5 = None;
    let mut user = None;
    let mut pass = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--socks5" if i + 1 < args.len() => { socks5 = Some(args[i + 1].clone()); i += 2; }
            "--user" if i + 1 < args.len() => { user = Some(args[i + 1].clone()); i += 2; }
            "--pass" if i + 1 < args.len() => { pass = Some(args[i + 1].clone()); i += 2; }
            _ => i += 1,
        }
    }
    socks5.map(|addr| {
        let (host, port) = if let Some(pos) = addr.rfind(':') {
            (addr[..pos].to_string(), addr[pos + 1..].parse().unwrap_or(1080))
        } else {
            (addr, 1080)
        };
        match (user, pass) {
            (Some(u), Some(p)) => ProxyConfig::socks5_with_auth(host, port, u, p),
            _ => ProxyConfig::socks5(host, port),
        }
    })
}
