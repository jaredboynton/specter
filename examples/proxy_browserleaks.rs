//! BrowserLeaks TLS fingerprint check through SOCKS5 proxy.
//!
//! Usage:
//!   cargo run --example proxy_browserleaks -- --socks5 host:port --user USER --pass PASS

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
        .prefer_http2(true)
        .with_platform_roots(true);

    if let Some(ref p) = proxy {
        println!("[*] Proxy: {}", p.proxy_key());
        builder = builder.proxy(p.clone());
    } else {
        println!("[*] Direct (no proxy)");
    }

    let client = builder.build()?;

    // 1. BrowserLeaks TLS fingerprint
    println!("\n=== tls.browserleaks.com/json ===");
    let headers = chrome_146_headers();
    match client
        .get("https://tls.browserleaks.com/json")
        .headers(headers.clone())
        .version(HttpVersion::Http2)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            println!("Status: {}", status);
            // Pretty-print the JSON
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(ja3_hash) = val.get("ja3_hash") {
                    println!("JA3 hash:        {}", ja3_hash);
                }
                if let Some(ja3n_hash) = val.get("ja3n_hash") {
                    println!("JA3N hash:       {}", ja3n_hash);
                }
                if let Some(ja4) = val.get("ja4") {
                    println!("JA4:             {}", ja4);
                }
                if let Some(akamai) = val.get("akamai_hash") {
                    println!("Akamai H2 hash:  {}", akamai);
                }
                if let Some(akamai_text) = val.get("akamai_text") {
                    println!("Akamai H2 text:  {}", akamai_text);
                }
                if let Some(tls_version) = val.get("tls_version") {
                    println!("TLS version:     {}", tls_version);
                }
                if let Some(protocol) = val.get("protocol") {
                    println!("HTTP protocol:   {}", protocol);
                }
                if let Some(ip) = val.get("ip") {
                    println!("IP:              {}", ip);
                }
            } else {
                println!("{}", body);
            }
        }
        Err(e) => println!("FAILED: {}", e),
    }

    // 2. tls.peet.ws for detailed fingerprint
    println!("\n=== tls.peet.ws/api/all ===");
    match client
        .get("https://tls.peet.ws/api/all")
        .headers(headers)
        .version(HttpVersion::Http2)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            println!("Status: {}", status);
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(ip) = val.get("ip") {
                    println!("IP:              {}", ip);
                }
                if let Some(ja3) = val.get("ja3_hash") {
                    println!("JA3 hash:        {}", ja3);
                }
                if let Some(ja4) = val.get("ja4") {
                    println!("JA4:             {}", ja4);
                }
                if let Some(h2) = val.get("http_version") {
                    println!("HTTP version:    {}", h2);
                }
                if let Some(akamai) = val.get("akamai") {
                    println!("Akamai fp:       {}", akamai);
                }
                if let Some(h2fp) = val.get("h2") {
                    if let Some(akamai_fp) = h2fp.get("akamai_fingerprint") {
                        println!("H2 Akamai fp:    {}", akamai_fp);
                    }
                }
            } else {
                println!("{}", body);
            }
        }
        Err(e) => println!("FAILED: {}", e),
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
            "--socks5" if i + 1 < args.len() => {
                socks5 = Some(args[i + 1].clone());
                i += 2;
            }
            "--user" if i + 1 < args.len() => {
                user = Some(args[i + 1].clone());
                i += 2;
            }
            "--pass" if i + 1 < args.len() => {
                pass = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }

    socks5.map(|addr| {
        let (host, port) = if let Some(pos) = addr.rfind(':') {
            (
                addr[..pos].to_string(),
                addr[pos + 1..].parse().unwrap_or(1080),
            )
        } else {
            (addr, 1080)
        };
        match (user, pass) {
            (Some(u), Some(p)) => ProxyConfig::socks5_with_auth(host, port, u, p),
            _ => ProxyConfig::socks5(host, port),
        }
    })
}
