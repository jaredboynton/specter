//! Fingerprint validation against detection services.
//!
//! Run with: cargo run --example fingerprint_validation
//!
//! Tests TLS and HTTP/2 fingerprints against:
//! - tls.browserleaks.com (TLS/JA3/Akamai fingerprint)
//! - tls.peet.ws (TLS fingerprint with detailed breakdown)
//! - tools.scrapfly.io (JA3/JA3N/Akamai format)
//!
//! Reference fingerprints (curl_cffi benchmarks):
//! - Python requests: 8d9f7747675e24454cd9b7ed35c58707 (detected as bot)
//! - cURL 7.x: e7d705a3286e19ea42f587b344ee6865 (detected as bot)
//! - curl_cffi Chrome: 579ccef312d18482fc42e2b822ca2430 (passes detection)
//!
//! HTTP/2 Akamai format: settings|window_update|priority|pseudo_headers
//! Chrome values: 1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p

use specter::error::Result;
use specter::fingerprint::http2::Http2Settings;
use specter::fingerprint::tls::TlsFingerprint;
use specter::transport::connector::{BoringConnector, MaybeHttpsStream};
use specter::transport::h2::{H2Connection, PseudoHeaderOrder};
use specter::transport::h3::H3Client;

use http::{Method, Uri};
use tracing::{error, info, warn};
use tracing_subscriber;

/// Known bot fingerprints to avoid
const BOT_JA3_PYTHON_REQUESTS: &str = "8d9f7747675e24454cd9b7ed35c58707";
const BOT_JA3_CURL_7X: &str = "e7d705a3286e19ea42f587b344ee6865";

/// Expected Chrome-like HTTP/2 Akamai format
const EXPECTED_AKAMAI_SETTINGS: &str = "1:65536;3:1000;4:6291456;6:262144";
const EXPECTED_WINDOW_UPDATE: &str = "15663105";
const EXPECTED_PSEUDO_ORDER: &str = "m,a,s,p";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("=== Specter Fingerprint Validation ===");

    // Test 1: TLS Fingerprint via BoringConnector
    info!("1. Testing TLS Fingerprint (BoringSSL)");
    info!("   Target: tls.peet.ws/api/all");
    test_tls_fingerprint().await?;

    // Test 2: HTTP/2 SETTINGS Fingerprint
    info!("2. Testing HTTP/2 SETTINGS Fingerprint");
    info!("   Target: tls.peet.ws/api/all (HTTP/2)");
    test_h2_fingerprint().await?;

    // Test 3: HTTP/3 Fingerprint
    info!("3. Testing HTTP/3 Fingerprint (QUIC/quiche)");
    info!("   Target: cloudflare.com (HTTP/3)");
    test_h3_fingerprint().await?;

    // Test 4: Full validation against browserleaks
    info!("4. Testing against browserleaks.com");
    test_browserleaks().await?;

    // Test 5: ScrapFly fingerprint service
    info!("5. Testing against ScrapFly");
    test_scrapfly().await?;

    // Test 6: Bot fingerprint comparison
    info!("6. Fingerprint Analysis Summary");
    print_fingerprint_summary();

    info!("=== Validation Complete ===");
    Ok(())
}

/// Test TLS fingerprint using BoringConnector
async fn test_tls_fingerprint() -> Result<()> {
    let fp = TlsFingerprint::chrome_142();

    info!("   Configured TLS Fingerprint:");
    info!("   - Cipher suites: {} configured", fp.cipher_list.len());
    info!("   - Signature algorithms: {} configured", fp.sigalgs.len());
    info!("   - Curves: {:?}", fp.curves);
    info!("   - GREASE: {}", fp.grease);

    // Create connector with fingerprint
    let connector = BoringConnector::with_fingerprint(fp);

    // Test connection to fingerprint service
    let uri: Uri = "https://tls.peet.ws/api/all".parse().unwrap();

    match connector.connect(&uri).await {
        Ok(stream) => {
            info!("   [OK] TLS connection established");

            // Check ALPN negotiation
            let alpn = stream.alpn_protocol();
            info!("   [OK] ALPN negotiated: {:?}", alpn);

            // Check if we got HTTPS
            match &stream {
                MaybeHttpsStream::Https(ssl_stream) => {
                    // Get cipher suite
                    if let Some(cipher) = ssl_stream.ssl().current_cipher() {
                        info!("   [OK] Cipher: {}", cipher.name());
                    }

                    // Get TLS version
                    info!("   [OK] TLS Version: {:?}", ssl_stream.ssl().version_str());
                }
                MaybeHttpsStream::Http(_) => {
                    warn!("   [WARN] Got plain HTTP instead of HTTPS");
                }
            }
        }
        Err(e) => {
            error!("   [ERROR] TLS connection failed: {}", e);
        }
    }

    Ok(())
}

/// Test HTTP/2 SETTINGS fingerprint
async fn test_h2_fingerprint() -> Result<()> {
    let settings = Http2Settings::default();

    info!("   Configured HTTP/2 SETTINGS:");
    info!("   - HEADER_TABLE_SIZE: {}", settings.header_table_size);
    info!("   - ENABLE_PUSH: {}", settings.enable_push);
    info!(
        "   - MAX_CONCURRENT_STREAMS: {}",
        settings.max_concurrent_streams
    );
    info!("   - INITIAL_WINDOW_SIZE: {}", settings.initial_window_size);
    info!("   - MAX_FRAME_SIZE: {}", settings.max_frame_size);
    info!(
        "   - MAX_HEADER_LIST_SIZE: {}",
        settings.max_header_list_size
    );

    // Expected Chrome values
    info!("   Expected Chrome 142 values:");
    info!(
        "   - HEADER_TABLE_SIZE: 65536 {}",
        check(settings.header_table_size == 65536)
    );
    info!("   - ENABLE_PUSH: false {}", check(!settings.enable_push));
    info!(
        "   - MAX_CONCURRENT_STREAMS: 1000 {}",
        check(settings.max_concurrent_streams == 1000)
    );
    info!(
        "   - INITIAL_WINDOW_SIZE: 6291456 {}",
        check(settings.initial_window_size == 6291456)
    );
    info!(
        "   - MAX_FRAME_SIZE: 16384 {}",
        check(settings.max_frame_size == 16384)
    );
    info!(
        "   - MAX_HEADER_LIST_SIZE: 262144 {}",
        check(settings.max_header_list_size == 262144)
    );

    // Expected Akamai format
    info!("   Expected Akamai HTTP/2 format:");
    info!(
        "   - SETTINGS: {} {}",
        EXPECTED_AKAMAI_SETTINGS, "[REFERENCE]"
    );
    info!(
        "   - WINDOW_UPDATE: {} {}",
        EXPECTED_WINDOW_UPDATE, "[REFERENCE]"
    );
    info!(
        "   - Pseudo-header order: {} {}",
        EXPECTED_PSEUDO_ORDER, "[REFERENCE]"
    );

    // Test actual HTTP/2 connection
    let fp = TlsFingerprint::chrome_142();
    let connector = BoringConnector::with_fingerprint(fp);
    let uri: Uri = "https://tls.peet.ws/api/all".parse().unwrap();

    match connector.connect(&uri).await {
        Ok(stream) => {
            // IMPORTANT: Check ALPN before attempting HTTP/2
            let alpn = stream.alpn_protocol();
            info!("   ALPN negotiated: {:?}", alpn);

            if !stream.is_h2() {
                warn!("   [WARN] Server did not negotiate HTTP/2 via ALPN, skipping H2 test");
                return Ok(());
            }

            // Create H2 connection with fingerprinted settings and Chrome pseudo-header order
            match H2Connection::connect(stream, settings.clone(), PseudoHeaderOrder::Chrome).await {
                Ok(mut h2_conn) => {
                    info!("   [OK] HTTP/2 connection established with custom SETTINGS");

                    // Send a request
                    let headers = vec![
                        (
                            "user-agent".to_string(),
                            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
                                .to_string(),
                        ),
                        ("accept".to_string(), "application/json".to_string()),
                    ];

                    match h2_conn.send_request(Method::GET, &uri, headers, None).await {
                        Ok(response) => {
                            info!("   [OK] HTTP/2 request succeeded: {}", response.status);

                            // Parse response to check fingerprint
                            let body = String::from_utf8_lossy(response.body());
                            if body.contains("h2") {
                                info!("   [OK] Server confirmed HTTP/2 connection");
                            }

                            // Try to extract fingerprint info from response
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                                if let Some(h2_fp) = json.get("http2") {
                                    info!("   Server-detected HTTP/2 fingerprint:");
                                    info!(
                                        "   {}",
                                        serde_json::to_string_pretty(h2_fp).unwrap_or_default()
                                    );

                                    // Check Akamai fingerprint if present
                                    if let Some(akamai) = h2_fp.get("akamai_fingerprint") {
                                        let akamai_str = akamai.as_str().unwrap_or("");
                                        validate_akamai_fingerprint(akamai_str);
                                    }
                                }
                                if let Some(tls_fp) = json.get("tls") {
                                    info!("   Server-detected TLS fingerprint:");
                                    if let Some(ja3) = tls_fp.get("ja3_hash") {
                                        let ja3_str = ja3.as_str().unwrap_or("");
                                        info!("   - JA3 Hash: {}", ja3);
                                        validate_ja3(ja3_str);
                                    }
                                    if let Some(ja4) = tls_fp.get("ja4") {
                                        info!("   - JA4: {}", ja4);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("   [ERROR] HTTP/2 request failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("   [ERROR] HTTP/2 connection failed: {}", e);
                }
            }
        }
        Err(e) => {
            error!("   [ERROR] TLS connection failed: {}", e);
        }
    }

    Ok(())
}

/// Test HTTP/3 fingerprint using quiche
async fn test_h3_fingerprint() -> Result<()> {
    let fp = TlsFingerprint::chrome_142();

    info!("   Configured HTTP/3 TLS Fingerprint:");
    info!("   - Cipher suites: {} configured", fp.cipher_list.len());
    info!("   - Curves: {:?}", fp.curves);
    info!("   - GREASE: {}", fp.grease);

    // Create H3 client with fingerprint
    let h3_client = H3Client::with_fingerprint(fp);

    // Test against Cloudflare (known HTTP/3 support)
    let url = "https://cloudflare.com/cdn-cgi/trace";

    info!("   Testing HTTP/3 connection to: {}", url);

    match h3_client
        .send_request(
            url,
            "GET",
            vec![
                (
                    "user-agent",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                ),
                ("accept", "*/*"),
            ],
            None,
        )
        .await
    {
        Ok(response) => {
            info!("   [OK] HTTP/3 request succeeded: {}", response.status);
            info!("   [OK] Protocol: {}", response.http_version());

            let body = String::from_utf8_lossy(response.body());
            info!("   Cloudflare trace response:");
            for line in body.lines().take(10) {
                info!("   {}", line);
            }

            // Check if we actually used HTTP/3
            if response.http_version() == "HTTP/3" {
                info!("   [OK] Confirmed HTTP/3 connection");
            } else {
                warn!("   [WARN] Did not use HTTP/3: {}", response.http_version());
            }
        }
        Err(e) => {
            error!("   [ERROR] HTTP/3 request failed: {}", e);
            info!("   Note: HTTP/3 requires UDP connectivity and server support");
        }
    }

    // Also try quic.tech for fingerprint detection
    info!("   Testing HTTP/3 fingerprint detection at quic.tech...");
    let quic_url = "https://quic.tech:8443/";

    match h3_client
        .send_request(
            quic_url,
            "GET",
            vec![
                (
                    "user-agent",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                ),
                ("accept", "text/html"),
            ],
            None,
        )
        .await
    {
        Ok(response) => {
            info!("   [OK] quic.tech response: {}", response.status);
            if response.http_version() == "HTTP/3" {
                info!("   [OK] HTTP/3 confirmed");
            }
        }
        Err(e) => {
            info!(
                "   [INFO] quic.tech test: {} (server may be unavailable)",
                e
            );
        }
    }

    Ok(())
}

/// Test against browserleaks.com TLS fingerprint service
async fn test_browserleaks() -> Result<()> {
    let fp = TlsFingerprint::chrome_142();
    let connector = BoringConnector::with_fingerprint(fp);
    let settings = Http2Settings::default();

    // browserleaks TLS endpoint
    let uri: Uri = "https://tls.browserleaks.com/json".parse().unwrap();

    info!("   Testing: {}", uri);

    match connector.connect(&uri).await {
        Ok(stream) => {
            // Check ALPN before attempting HTTP/2
            let alpn = stream.alpn_protocol();
            info!("   ALPN negotiated: {:?}", alpn);

            if !stream.is_h2() {
                warn!("   [WARN] Server did not negotiate HTTP/2 via ALPN, skipping test");
                return Ok(());
            }

            match H2Connection::connect(stream, settings, PseudoHeaderOrder::Chrome).await {
                Ok(mut h2_conn) => {
                    let headers = vec![
                        ("user-agent".to_string(), "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36".to_string()),
                        ("accept".to_string(), "application/json".to_string()),
                        ("accept-language".to_string(), "en-US,en;q=0.9".to_string()),
                    ];

                    match h2_conn.send_request(Method::GET, &uri, headers, None).await {
                        Ok(response) => {
                            info!("   [OK] Response: {}", response.status);

                            let body = String::from_utf8_lossy(response.body());

                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                                info!("   Browserleaks TLS Fingerprint Results:");

                                if let Some(ja3) = json.get("ja3_hash") {
                                    let ja3_str = ja3.as_str().unwrap_or("");
                                    info!("   - JA3 Hash: {}", ja3);
                                    validate_ja3(ja3_str);
                                }
                                if let Some(ja3_text) = json.get("ja3_text") {
                                    info!("   - JA3 Text: {}", ja3_text);
                                }
                                if let Some(ja3n) = json.get("ja3n_hash") {
                                    info!("   - JA3N Hash: {}", ja3n);
                                }
                                if let Some(ja4) = json.get("ja4") {
                                    info!("   - JA4: {}", ja4);
                                }
                                if let Some(akamai) = json.get("akamai_hash") {
                                    info!("   - Akamai Hash: {}", akamai);
                                }
                                if let Some(akamai_fp) = json.get("akamai_fingerprint") {
                                    let akamai_str = akamai_fp.as_str().unwrap_or("");
                                    info!("   - Akamai Fingerprint: {}", akamai_fp);
                                    validate_akamai_fingerprint(akamai_str);
                                }
                                if let Some(tls_version) = json.get("tls_version") {
                                    info!("   - TLS Version: {}", tls_version);
                                }
                                if let Some(cipher) = json.get("cipher_suite") {
                                    info!("   - Cipher Suite: {}", cipher);
                                }

                                // Check for Chrome-like fingerprint
                                if let Some(user_agent_match) = json.get("user_agent_match") {
                                    let ua_match = user_agent_match.as_bool().unwrap_or(false);
                                    info!("   User-Agent Match: {} {}", ua_match, check(ua_match));
                                }
                            } else {
                                info!(
                                    "   Response body (raw):\n   {}",
                                    &body[..body.len().min(500)]
                                );
                            }
                        }
                        Err(e) => {
                            error!("   [ERROR] Request failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("   [ERROR] HTTP/2 connection failed: {}", e);
                }
            }
        }
        Err(e) => {
            error!("   [ERROR] TLS connection failed: {}", e);
        }
    }

    Ok(())
}

/// Test against ScrapFly fingerprint service
async fn test_scrapfly() -> Result<()> {
    let fp = TlsFingerprint::chrome_142();
    let connector = BoringConnector::with_fingerprint(fp);
    let settings = Http2Settings::default();

    // ScrapFly fingerprint endpoint
    let uri: Uri = "https://tools.scrapfly.io/api/fp/ja3".parse().unwrap();

    info!("   Testing: {}", uri);

    match connector.connect(&uri).await {
        Ok(stream) => {
            // Check ALPN before attempting HTTP/2
            let alpn = stream.alpn_protocol();
            info!("   ALPN negotiated: {:?}", alpn);

            if !stream.is_h2() {
                warn!("   [WARN] Server did not negotiate HTTP/2 via ALPN, skipping test");
                return Ok(());
            }

            match H2Connection::connect(stream, settings, PseudoHeaderOrder::Chrome).await {
                Ok(mut h2_conn) => {
                    let headers = vec![
                        ("user-agent".to_string(), "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36".to_string()),
                        ("accept".to_string(), "application/json".to_string()),
                        ("accept-language".to_string(), "en-US,en;q=0.9".to_string()),
                    ];

                    match h2_conn.send_request(Method::GET, &uri, headers, None).await {
                        Ok(response) => {
                            info!("   [OK] Response: {}", response.status);

                            let body = String::from_utf8_lossy(response.body());

                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                                info!("   ScrapFly Fingerprint Results:");

                                if let Some(ja3) = json.get("ja3") {
                                    let ja3_str = ja3.as_str().unwrap_or("");
                                    info!("   - JA3 Hash: {}", ja3);
                                    validate_ja3(ja3_str);
                                }
                                if let Some(ja3_digest) = json.get("ja3_digest") {
                                    info!("   - JA3 Digest: {}", ja3_digest);
                                }
                                if let Some(ja3n) = json.get("ja3n") {
                                    info!("   - JA3N: {}", ja3n);
                                }
                                if let Some(ja3n_digest) = json.get("ja3n_digest") {
                                    info!("   - JA3N Digest: {}", ja3n_digest);
                                }
                                if let Some(akamai) = json.get("akamai") {
                                    let akamai_str = akamai.as_str().unwrap_or("");
                                    info!("   - Akamai: {}", akamai);
                                    validate_akamai_fingerprint(akamai_str);
                                }
                                if let Some(akamai_digest) = json.get("akamai_digest") {
                                    info!("   - Akamai Digest: {}", akamai_digest);
                                }
                                if let Some(scrapfly_fp) = json.get("scrapfly_fp") {
                                    info!("   - ScrapFly FP: {}", scrapfly_fp);
                                }
                                if let Some(scrapfly_fp_digest) = json.get("scrapfly_fp_digest") {
                                    info!("   - ScrapFly FP Digest: {}", scrapfly_fp_digest);
                                }

                                // HTTP/2 specific
                                if let Some(h2_settings) = json.get("h2_settings") {
                                    info!("   - HTTP/2 SETTINGS: {}", h2_settings);
                                }
                                if let Some(h2_window) = json.get("h2_window_update") {
                                    info!("   - HTTP/2 WINDOW_UPDATE: {}", h2_window);
                                }
                                if let Some(h2_pseudo) = json.get("h2_pseudo_header_order") {
                                    info!("   - HTTP/2 Pseudo Order: {}", h2_pseudo);
                                }
                            } else {
                                info!(
                                    "   Response body (raw):\n   {}",
                                    &body[..body.len().min(500)]
                                );
                            }
                        }
                        Err(e) => {
                            error!("   [ERROR] Request failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("   [ERROR] HTTP/2 connection failed: {}", e);
                }
            }
        }
        Err(e) => {
            error!("   [ERROR] TLS connection failed: {}", e);
        }
    }

    Ok(())
}

/// Validate JA3 fingerprint against known bot signatures
fn validate_ja3(ja3: &str) {
    if ja3 == BOT_JA3_PYTHON_REQUESTS {
        error!("     [FAIL] Matches Python requests bot fingerprint!");
    } else if ja3 == BOT_JA3_CURL_7X {
        error!("     [FAIL] Matches cURL 7.x bot fingerprint!");
    } else {
        info!("     [OK] Does not match known bot fingerprints");
    }
}

/// Validate Akamai HTTP/2 fingerprint format
fn validate_akamai_fingerprint(akamai: &str) {
    // Akamai format: settings|window_update|priority|pseudo_headers
    let parts: Vec<&str> = akamai.split('|').collect();
    if parts.len() >= 4 {
        info!("     Akamai Validation:");
        info!(
            "       - SETTINGS: {} {}",
            parts[0],
            if parts[0] == EXPECTED_AKAMAI_SETTINGS {
                "[OK]"
            } else {
                "[DIFFERS]"
            }
        );
        info!(
            "       - WINDOW_UPDATE: {} {}",
            parts[1],
            if parts[1] == EXPECTED_WINDOW_UPDATE {
                "[OK]"
            } else {
                "[DIFFERS]"
            }
        );
        // Priority (parts[2]) varies
        info!(
            "       - Pseudo order: {} {}",
            parts[3],
            if parts[3] == EXPECTED_PSEUDO_ORDER {
                "[OK]"
            } else {
                "[DIFFERS]"
            }
        );
    }
}

/// Print summary of fingerprint expectations
fn print_fingerprint_summary() {
    info!("   Reference Fingerprints (for comparison):");
    info!("");
    info!("   Known BOT fingerprints (should NOT match):");
    info!("   - Python requests: {}", BOT_JA3_PYTHON_REQUESTS);
    info!("   - cURL 7.x:        {}", BOT_JA3_CURL_7X);
    info!("");
    info!("   Expected HTTP/2 Akamai format (Chrome):");
    info!("   - SETTINGS:        {}", EXPECTED_AKAMAI_SETTINGS);
    info!("   - WINDOW_UPDATE:   {}", EXPECTED_WINDOW_UPDATE);
    info!("   - Pseudo order:    {}", EXPECTED_PSEUDO_ORDER);
    info!("");
    info!("   HTTP/2 SETTINGS breakdown:");
    info!("   - 1 = HEADER_TABLE_SIZE:    65536");
    info!("   - 3 = MAX_CONCURRENT_STREAMS: 1000");
    info!("   - 4 = INITIAL_WINDOW_SIZE:  6291456");
    info!("   - 6 = MAX_HEADER_LIST_SIZE: 262144");
}

fn check(condition: bool) -> &'static str {
    if condition {
        "[OK]"
    } else {
        "[MISMATCH]"
    }
}
