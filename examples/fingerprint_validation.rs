//! Fingerprint validation against detection services.
//!
//! Run with: cargo run --example fingerprint_validation
//!
//! Tests TLS and HTTP/2 fingerprints against:
//! - tls.browserleaks.com (TLS/JA3 fingerprint)
//! - tls.peet.ws (TLS fingerprint with detailed breakdown)

use specter::fingerprint::tls::TlsFingerprint;
use specter::fingerprint::http2::Http2Settings;
use specter::transport::connector::BoringConnector;
use specter::transport::h2_native::{H2Connection, PseudoHeaderOrder};
use specter::transport::h3::H3Client;
use specter::error::Result;

use http::{Method, Uri};
use tower::Service;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Specter Fingerprint Validation ===\n");

    // Test 1: TLS Fingerprint via BoringConnector
    println!("1. Testing TLS Fingerprint (BoringSSL)");
    println!("   Target: tls.peet.ws/api/all");
    test_tls_fingerprint().await?;

    // Test 2: HTTP/2 SETTINGS Fingerprint
    println!("\n2. Testing HTTP/2 SETTINGS Fingerprint");
    println!("   Target: tls.peet.ws/api/all (HTTP/2)");
    test_h2_fingerprint().await?;

    // Test 3: HTTP/3 Fingerprint (EXPERIMENTAL - Currently non-functional)
    println!("\n3. Testing HTTP/3 Fingerprint (QUIC/quiche) - EXPERIMENTAL");
    println!("   Target: cloudflare.com (HTTP/3)");
    println!("   NOTE: HTTP/3 implementation is non-functional. QUIC handshake succeeds");
    println!("   but h3.poll() never returns response events. Use HTTP/2 for production.");
    test_h3_fingerprint().await?;

    // Test 4: Full validation against browserleaks
    println!("\n4. Testing against browserleaks.com");
    test_browserleaks().await?;

    println!("\n=== Validation Complete ===");
    Ok(())
}

/// Test TLS fingerprint using BoringConnector
async fn test_tls_fingerprint() -> Result<()> {
    let fp = TlsFingerprint::chrome_131();

    println!("   Configured TLS Fingerprint:");
    println!("   - Cipher suites: {} configured", fp.cipher_list.len());
    println!("   - Signature algorithms: {} configured", fp.sigalgs.len());
    println!("   - Curves: {:?}", fp.curves);
    println!("   - GREASE: {}", fp.grease);

    // Create connector with fingerprint
    let mut connector = BoringConnector::with_fingerprint(fp);

    // Test connection to fingerprint service
    let uri: Uri = "https://tls.peet.ws/api/all".parse().unwrap();

    match connector.call(uri.clone()).await {
        Ok(stream) => {
            println!("   [OK] TLS connection established");

            // Check if we got HTTPS
            match &stream {
                specter::transport::connector::MaybeHttpsStream::Https(ssl_stream) => {
                    // Get negotiated protocol
                    if let Some(alpn) = ssl_stream.ssl().selected_alpn_protocol() {
                        println!("   [OK] ALPN negotiated: {}", String::from_utf8_lossy(alpn));
                    }

                    // Get cipher suite
                    if let Some(cipher) = ssl_stream.ssl().current_cipher() {
                        println!("   [OK] Cipher: {}", cipher.name());
                    }

                    // Get TLS version
                    println!("   [OK] TLS Version: {:?}", ssl_stream.ssl().version_str());
                }
                specter::transport::connector::MaybeHttpsStream::Http(_) => {
                    println!("   [WARN] Got plain HTTP instead of HTTPS");
                }
            }
        }
        Err(e) => {
            println!("   [ERROR] TLS connection failed: {}", e);
        }
    }

    Ok(())
}

/// Test HTTP/2 SETTINGS fingerprint
async fn test_h2_fingerprint() -> Result<()> {
    let settings = Http2Settings::default();

    println!("   Configured HTTP/2 SETTINGS:");
    println!("   - HEADER_TABLE_SIZE: {}", settings.header_table_size);
    println!("   - ENABLE_PUSH: {}", settings.enable_push);
    println!("   - MAX_CONCURRENT_STREAMS: {}", settings.max_concurrent_streams);
    println!("   - INITIAL_WINDOW_SIZE: {}", settings.initial_window_size);
    println!("   - MAX_FRAME_SIZE: {}", settings.max_frame_size);
    println!("   - MAX_HEADER_LIST_SIZE: {}", settings.max_header_list_size);

    // Expected Chrome values
    println!("\n   Expected Chrome 131+ values:");
    println!("   - HEADER_TABLE_SIZE: 65536 {}", check(settings.header_table_size == 65536));
    println!("   - ENABLE_PUSH: false {}", check(!settings.enable_push));
    println!("   - MAX_CONCURRENT_STREAMS: 1000 {}", check(settings.max_concurrent_streams == 1000));
    println!("   - INITIAL_WINDOW_SIZE: 6291456 {}", check(settings.initial_window_size == 6291456));
    println!("   - MAX_FRAME_SIZE: 16384 {}", check(settings.max_frame_size == 16384));
    println!("   - MAX_HEADER_LIST_SIZE: 262144 {}", check(settings.max_header_list_size == 262144));

    // Test actual HTTP/2 connection
    let fp = TlsFingerprint::chrome_131();
    let mut connector = BoringConnector::with_fingerprint(fp);
    let uri: Uri = "https://tls.peet.ws/api/all".parse().unwrap();

    match connector.call(uri.clone()).await {
        Ok(stream) => {
            // Create H2 connection with fingerprinted settings
            match H2Connection::connect(stream, settings.clone(), PseudoHeaderOrder::Chrome).await {
                Ok(mut h2_conn) => {
                    println!("\n   [OK] HTTP/2 connection established with custom SETTINGS");

                    // Send a request
                    let headers = vec![
                        ("user-agent".to_string(), "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string()),
                        ("accept".to_string(), "application/json".to_string()),
                    ];

                    match h2_conn.send_request(Method::GET, &uri, headers, None).await {
                        Ok(response) => {
                            println!("   [OK] HTTP/2 request succeeded: {}", response.status);

                            // Parse response to check fingerprint
                            let body = String::from_utf8_lossy(response.body());
                            if body.contains("h2") {
                                println!("   [OK] Server confirmed HTTP/2 connection");
                            }

                            // Try to extract fingerprint info from response
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                                if let Some(h2_fp) = json.get("http2") {
                                    println!("\n   Server-detected HTTP/2 fingerprint:");
                                    println!("   {}", serde_json::to_string_pretty(h2_fp).unwrap_or_default());
                                }
                                if let Some(tls_fp) = json.get("tls") {
                                    println!("\n   Server-detected TLS fingerprint:");
                                    if let Some(ja3) = tls_fp.get("ja3_hash") {
                                        println!("   - JA3 Hash: {}", ja3);
                                    }
                                    if let Some(ja4) = tls_fp.get("ja4") {
                                        println!("   - JA4: {}", ja4);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            println!("   [ERROR] HTTP/2 request failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("   [ERROR] HTTP/2 connection failed: {}", e);
                }
            }
        }
        Err(e) => {
            println!("   [ERROR] TLS connection failed: {}", e);
        }
    }

    Ok(())
}

/// Test HTTP/3 fingerprint using quiche
async fn test_h3_fingerprint() -> Result<()> {
    let fp = TlsFingerprint::chrome_131();

    println!("   Configured HTTP/3 TLS Fingerprint:");
    println!("   - Cipher suites: {} configured", fp.cipher_list.len());
    println!("   - Curves: {:?}", fp.curves);
    println!("   - GREASE: {}", fp.grease);

    // Create H3 client with fingerprint
    let h3_client = H3Client::with_fingerprint(fp);

    // Test against Cloudflare (known HTTP/3 support)
    let url = "https://cloudflare.com/cdn-cgi/trace";

    println!("\n   Testing HTTP/3 connection to: {}", url);

    match h3_client.send_request(
        url,
        "GET",
        vec![
            ("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"),
            ("accept", "*/*"),
        ],
        None,
    ).await {
        Ok(response) => {
            println!("   [OK] HTTP/3 request succeeded: {}", response.status);
            println!("   [OK] Protocol: {}", response.http_version());

            let body = String::from_utf8_lossy(response.body());
            println!("\n   Cloudflare trace response:");
            for line in body.lines().take(10) {
                println!("   {}", line);
            }

            // Check if we actually used HTTP/3
            if response.http_version() == "HTTP/3" {
                println!("\n   [OK] Confirmed HTTP/3 connection");
            } else {
                println!("\n   [WARN] Did not use HTTP/3: {}", response.http_version());
            }
        }
        Err(e) => {
            println!("   [ERROR] HTTP/3 request failed: {}", e);
            println!("   Note: HTTP/3 requires UDP connectivity and server support");
        }
    }

    // Also try quic.tech for fingerprint detection
    println!("\n   Testing HTTP/3 fingerprint detection at quic.tech...");
    let quic_url = "https://quic.tech:8443/";

    match h3_client.send_request(
        quic_url,
        "GET",
        vec![
            ("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"),
            ("accept", "text/html"),
        ],
        None,
    ).await {
        Ok(response) => {
            println!("   [OK] quic.tech response: {}", response.status);
            if response.http_version() == "HTTP/3" {
                println!("   [OK] HTTP/3 confirmed");
            }
        }
        Err(e) => {
            println!("   [INFO] quic.tech test: {} (server may be unavailable)", e);
        }
    }

    Ok(())
}

/// Test against browserleaks.com TLS fingerprint service
async fn test_browserleaks() -> Result<()> {
    let fp = TlsFingerprint::chrome_131();
    let mut connector = BoringConnector::with_fingerprint(fp);
    let settings = Http2Settings::default();

    // browserleaks TLS endpoint
    let uri: Uri = "https://tls.browserleaks.com/json".parse().unwrap();

    println!("   Testing: {}", uri);

    match connector.call(uri.clone()).await {
        Ok(stream) => {
            match H2Connection::connect(stream, settings, PseudoHeaderOrder::Chrome).await {
                Ok(mut h2_conn) => {
                    let headers = vec![
                        ("user-agent".to_string(), "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string()),
                        ("accept".to_string(), "application/json".to_string()),
                        ("accept-language".to_string(), "en-US,en;q=0.9".to_string()),
                    ];

                    match h2_conn.send_request(Method::GET, &uri, headers, None).await {
                        Ok(response) => {
                            println!("   [OK] Response: {}", response.status);

                            let body = String::from_utf8_lossy(response.body());

                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                                println!("\n   Browserleaks TLS Fingerprint Results:");

                                if let Some(ja3) = json.get("ja3_hash") {
                                    println!("   - JA3 Hash: {}", ja3);
                                }
                                if let Some(ja3_text) = json.get("ja3_text") {
                                    println!("   - JA3 Text: {}", ja3_text);
                                }
                                if let Some(ja4) = json.get("ja4") {
                                    println!("   - JA4: {}", ja4);
                                }
                                if let Some(akamai) = json.get("akamai_hash") {
                                    println!("   - Akamai Hash: {}", akamai);
                                }
                                if let Some(tls_version) = json.get("tls_version") {
                                    println!("   - TLS Version: {}", tls_version);
                                }
                                if let Some(cipher) = json.get("cipher_suite") {
                                    println!("   - Cipher Suite: {}", cipher);
                                }

                                // Check for Chrome-like fingerprint
                                if let Some(user_agent_match) = json.get("user_agent_match") {
                                    let ua_match = user_agent_match.as_bool().unwrap_or(false);
                                    println!("\n   User-Agent Match: {} {}", ua_match, check(ua_match));
                                }
                            } else {
                                println!("   Response body (raw):\n   {}", &body[..body.len().min(500)]);
                            }
                        }
                        Err(e) => {
                            println!("   [ERROR] Request failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("   [ERROR] HTTP/2 connection failed: {}", e);
                }
            }
        }
        Err(e) => {
            println!("   [ERROR] TLS connection failed: {}", e);
        }
    }

    Ok(())
}

fn check(condition: bool) -> &'static str {
    if condition { "[OK]" } else { "[MISMATCH]" }
}
