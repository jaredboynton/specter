//! Proxy integration test — hits IP detection APIs.
//!
//! Usage:
//!   # Without proxy (direct):
//!   cargo run --example proxy_test
//!
//!   # With SOCKS5 proxy:
//!   cargo run --example proxy_test -- --socks5 127.0.0.1:1080
//!
//!   # With SOCKS5 proxy + auth:
//!   cargo run --example proxy_test -- --socks5 127.0.0.1:1080 --user admin --pass secret
//!
//!   # With HTTP CONNECT proxy:
//!   cargo run --example proxy_test -- --http-proxy 127.0.0.1:8080

use specter::{Client, FingerprintProfile, ProxyConfig};

#[tokio::main]
async fn main() -> Result<(), specter::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("specter=debug".parse().unwrap()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let proxy = parse_proxy_args(&args);

    // Build client
    let mut builder = Client::builder()
        .fingerprint(FingerprintProfile::Chrome146)
        .with_platform_roots(true);

    if let Some(ref p) = proxy {
        println!("[*] Using proxy: {:?}", p);
        builder = builder.proxy(p.clone());
    } else {
        println!("[*] Direct connection (no proxy)");
    }

    let client = builder.build()?;

    // Hit IP detection APIs
    let apis = [
        ("httpbin.org/ip", "https://httpbin.org/ip"),
        ("api.ipify.org", "https://api.ipify.org?format=json"),
        ("ifconfig.me", "https://ifconfig.me/ip"),
    ];

    for (name, url) in &apis {
        print!("[>] {} ... ", name);
        match client.get(*url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().unwrap_or_else(|_| "(decode error)".into());
                println!("HTTP {} — {}", status, body.trim());
            }
            Err(e) => {
                println!("FAILED — {}", e);
            }
        }
    }

    Ok(())
}

fn parse_proxy_args(args: &[String]) -> Option<ProxyConfig> {
    let mut socks5_addr = None;
    let mut http_proxy_addr = None;
    let mut user = None;
    let mut pass = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--socks5" if i + 1 < args.len() => {
                socks5_addr = Some(args[i + 1].clone());
                i += 2;
            }
            "--http-proxy" if i + 1 < args.len() => {
                http_proxy_addr = Some(args[i + 1].clone());
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
            _ => {
                i += 1;
            }
        }
    }

    if let Some(addr) = socks5_addr {
        let (host, port) = parse_host_port(&addr, 1080);
        match (user, pass) {
            (Some(u), Some(p)) => Some(ProxyConfig::socks5_with_auth(host, port, u, p)),
            _ => Some(ProxyConfig::socks5(host, port)),
        }
    } else if let Some(addr) = http_proxy_addr {
        let (host, port) = parse_host_port(&addr, 8080);
        match (user, pass) {
            (Some(u), Some(p)) => Some(ProxyConfig::http_connect_with_auth(host, port, u, p)),
            _ => Some(ProxyConfig::http_connect(host, port)),
        }
    } else {
        None
    }
}

fn parse_host_port(addr: &str, default_port: u16) -> (String, u16) {
    if let Some(pos) = addr.rfind(':') {
        let host = addr[..pos].to_string();
        let port = addr[pos + 1..].parse().unwrap_or(default_port);
        (host, port)
    } else {
        (addr.to_string(), default_port)
    }
}
