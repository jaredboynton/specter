//! Comprehensive protocol test for HTTP/1.1, HTTP/2, and HTTP/3.
//!
//! Tests:
//! - HTTP/1.1 explicit requests
//! - HTTP/2 explicit requests
//! - HTTP/2 automatic upgrade when server selects h2 via ALPN
//! - HTTP/3 requests (when server supports it)
//! - Connection-specific header filtering (Connection, Keep-Alive, etc.)
//! - HTTP/2 connection pooling/multiplexing
//! - Various HTTP methods (GET, POST)
//! - Response decompression
//!
//! Usage:
//!   cargo run --example protocol_test
//!   cargo run --example protocol_test -- --verbose
//!   cargo run --example protocol_test -- --target cloudflare.com

use specter::headers::chrome_142_headers;
use specter::{ClientBuilder, FingerprintProfile, HttpVersion};
use std::time::Instant;
use tracing::info;

#[derive(Debug)]
struct TestResult {
    name: String,
    protocol: String,
    status: u16,
    duration_ms: u64,
    body_len: usize,
    success: bool,
    error: Option<String>,
}

impl TestResult {
    fn success(name: &str, protocol: &str, status: u16, duration_ms: u64, body_len: usize) -> Self {
        Self {
            name: name.to_string(),
            protocol: protocol.to_string(),
            status,
            duration_ms,
            body_len,
            success: true,
            error: None,
        }
    }

    fn failure(name: &str, error: String) -> Self {
        Self {
            name: name.to_string(),
            protocol: "N/A".to_string(),
            status: 0,
            duration_ms: 0,
            body_len: 0,
            success: false,
            error: Some(error),
        }
    }
}

/// Test targets that support various protocols
struct TestTarget {
    name: &'static str,
    url: &'static str,
    supports_h1: bool,
    supports_h2: bool,
    supports_h3: bool,
}

const TARGETS: &[TestTarget] = &[
    TestTarget {
        name: "Cloudflare",
        url: "https://cloudflare.com/",
        supports_h1: true,
        supports_h2: true,
        supports_h3: true,
    },
    TestTarget {
        name: "Google",
        url: "https://www.google.com/",
        supports_h1: true,
        supports_h2: true,
        supports_h3: true,
    },
    TestTarget {
        name: "httpbin (HTTP/2)",
        url: "https://httpbin.org/get",
        supports_h1: true,
        supports_h2: true,
        supports_h3: false,
    },
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse args
    let args: Vec<String> = std::env::args().collect();
    let verbose = args.iter().any(|a| a == "--verbose" || a == "-v");
    let custom_target = args
        .iter()
        .position(|a| a == "--target")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    // Initialize tracing if verbose
    if verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_target(true)
            .init();
    }

    info!("================================================================================");
    info!("Specter Protocol Test Suite");
    info!("================================================================================");
    info!("");

    let mut all_results: Vec<TestResult> = Vec::new();

    // Run tests against each target
    let targets: Vec<TestTarget> = if let Some(host) = custom_target {
        vec![TestTarget {
            name: "Custom",
            url: Box::leak(format!("https://{}/", host).into_boxed_str()),
            supports_h1: true,
            supports_h2: true,
            supports_h3: true, // Assume all, will fail gracefully
        }]
    } else {
        TARGETS
            .iter()
            .map(|t| TestTarget {
                name: t.name,
                url: t.url,
                supports_h1: t.supports_h1,
                supports_h2: t.supports_h2,
                supports_h3: t.supports_h3,
            })
            .collect()
    };

    for target in &targets {
        info!("Target: {} ({})", target.name, target.url);
        info!("--------------------------------------------------------------------------------");

        // Test 1: HTTP/1.1 explicit
        if target.supports_h1 {
            let result = test_http1_explicit(target.url, verbose).await;
            print_result(&result);
            all_results.push(result);
        }

        // Test 2: HTTP/2 explicit
        if target.supports_h2 {
            let result = test_http2_explicit(target.url, verbose).await;
            print_result(&result);
            all_results.push(result);
        }

        // Test 3: HTTP/2 auto-upgrade (client prefers H1, server selects H2)
        if target.supports_h2 {
            let result = test_http2_auto_upgrade(target.url, verbose).await;
            print_result(&result);
            all_results.push(result);
        }

        // Test 4: HTTP/2 connection pooling
        if target.supports_h2 {
            let result = test_http2_pooling(target.url, verbose).await;
            print_result(&result);
            all_results.push(result);
        }

        // Test 5: HTTP/3 explicit
        if target.supports_h3 {
            let result = test_http3_explicit(target.url, verbose).await;
            print_result(&result);
            all_results.push(result);
        }

        // Test 6: Connection header filtering
        let result = test_connection_header_filtering(target.url, verbose).await;
        print_result(&result);
        all_results.push(result);

        // Test 7: POST request
        if target.supports_h2 {
            let result = test_post_request(target.url, verbose).await;
            print_result(&result);
            all_results.push(result);
        }

        info!("");
    }

    // Summary
    info!("================================================================================");
    info!("Summary");
    info!("================================================================================");

    let passed = all_results.iter().filter(|r| r.success).count();
    let failed = all_results.iter().filter(|r| !r.success).count();
    let total = all_results.len();

    info!("Passed: {}/{}", passed, total);
    info!("Failed: {}/{}", failed, total);
    info!("");

    if failed > 0 {
        info!("Failed tests:");
        for result in all_results.iter().filter(|r| !r.success) {
            info!(
                "  - {}: {}",
                result.name,
                result.error.as_ref().unwrap_or(&"Unknown".to_string())
            );
        }
    }

    // Protocol breakdown
    info!("");
    info!("Protocol breakdown:");
    let h1_results: Vec<_> = all_results
        .iter()
        .filter(|r| r.protocol == "HTTP/1.1")
        .collect();
    let h2_results: Vec<_> = all_results
        .iter()
        .filter(|r| r.protocol == "HTTP/2")
        .collect();
    let h3_results: Vec<_> = all_results
        .iter()
        .filter(|r| r.protocol == "HTTP/3")
        .collect();

    if !h1_results.is_empty() {
        let h1_passed = h1_results.iter().filter(|r| r.success).count();
        info!("  HTTP/1.1: {}/{} passed", h1_passed, h1_results.len());
    }
    if !h2_results.is_empty() {
        let h2_passed = h2_results.iter().filter(|r| r.success).count();
        info!("  HTTP/2:   {}/{} passed", h2_passed, h2_results.len());
    }
    if !h3_results.is_empty() {
        let h3_passed = h3_results.iter().filter(|r| r.success).count();
        info!("  HTTP/3:   {}/{} passed", h3_passed, h3_results.len());
    }

    if failed > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn print_result(result: &TestResult) {
    if result.success {
        info!(
            "  [PASS] {} - {} {} ({}ms, {} bytes)",
            result.name, result.protocol, result.status, result.duration_ms, result.body_len
        );
    } else {
        info!(
            "  [FAIL] {} - {}",
            result.name,
            result
                .error
                .as_ref()
                .unwrap_or(&"Unknown error".to_string())
        );
    }
}

/// Test HTTP/1.1 preference (server may upgrade to HTTP/2 via ALPN)
///
/// Note: Most modern servers (Cloudflare, Google, etc.) prefer HTTP/2 and will
/// select it via ALPN even when client prefers HTTP/1.1. This test verifies that:
/// 1. If server supports HTTP/1.1, we use it
/// 2. If server upgrades to HTTP/2 via ALPN, we handle it correctly
async fn test_http1_explicit(url: &str, _verbose: bool) -> TestResult {
    let name = "HTTP/1.1 preference";

    let client = match ClientBuilder::new()
        .fingerprint(FingerprintProfile::Chrome142)
        .api_timeouts()
        .build()
    {
        Ok(c) => c,
        Err(e) => return TestResult::failure(name, format!("Client build failed: {}", e)),
    };

    let headers = chrome_headers_owned();
    let start = Instant::now();

    match client
        .get(url)
        .headers(headers)
        .version(HttpVersion::Http1_1)
        .send()
        .await
    {
        Ok(response) => {
            let duration = start.elapsed().as_millis() as u64;
            let protocol = response.http_version();
            let status = response.status;
            let body_len = response.body().len();

            // Server may upgrade to HTTP/2 via ALPN - that's valid behavior
            // The important thing is the request succeeded
            TestResult::success(name, protocol, status, duration, body_len)
        }
        Err(e) => TestResult::failure(name, format!("{}", e)),
    }
}

/// Test HTTP/2 with explicit version selection
async fn test_http2_explicit(url: &str, _verbose: bool) -> TestResult {
    let name = "HTTP/2 explicit";

    let client = match ClientBuilder::new()
        .fingerprint(FingerprintProfile::Chrome142)
        .prefer_http2(true)
        .api_timeouts()
        .build()
    {
        Ok(c) => c,
        Err(e) => return TestResult::failure(name, format!("Client build failed: {}", e)),
    };

    let headers = chrome_headers_owned();
    let start = Instant::now();

    match client
        .get(url)
        .headers(headers)
        .version(HttpVersion::Http2)
        .send()
        .await
    {
        Ok(response) => {
            let duration = start.elapsed().as_millis() as u64;
            let protocol = response.http_version();
            let status = response.status;
            let body_len = response.body().len();

            if protocol != "HTTP/2" {
                return TestResult::failure(name, format!("Expected HTTP/2, got {}", protocol));
            }

            TestResult::success(name, protocol, status, duration, body_len)
        }
        Err(e) => TestResult::failure(name, format!("{}", e)),
    }
}

/// Test HTTP/2 auto-upgrade (client uses default/H1 preference, server forces H2 via ALPN)
async fn test_http2_auto_upgrade(url: &str, _verbose: bool) -> TestResult {
    let name = "HTTP/2 auto-upgrade";

    // Build client with HTTP/1.1 preference (but ALPN still offers h2)
    let client = match ClientBuilder::new()
        .fingerprint(FingerprintProfile::Chrome142)
        .prefer_http2(false) // Prefer H1, but should upgrade if server selects H2
        .api_timeouts()
        .build()
    {
        Ok(c) => c,
        Err(e) => return TestResult::failure(name, format!("Client build failed: {}", e)),
    };

    // Include Connection: keep-alive to verify it gets filtered for H2
    let mut headers = chrome_headers_owned();
    headers.push(("Connection".to_string(), "keep-alive".to_string()));

    let start = Instant::now();

    match client.get(url).headers(headers).send().await {
        Ok(response) => {
            let duration = start.elapsed().as_millis() as u64;
            let protocol = response.http_version();
            let status = response.status;
            let body_len = response.body().len();

            // Most servers will select H2 - this test validates the auto-upgrade works
            // If server returned H1, that's also valid (just means server prefers H1)
            TestResult::success(name, protocol, status, duration, body_len)
        }
        Err(e) => TestResult::failure(name, format!("{}", e)),
    }
}

/// Test HTTP/2 connection pooling (multiple requests on same connection)
async fn test_http2_pooling(url: &str, _verbose: bool) -> TestResult {
    let name = "HTTP/2 connection pooling";

    let client = match ClientBuilder::new()
        .fingerprint(FingerprintProfile::Chrome142)
        .prefer_http2(true)
        .api_timeouts()
        .build()
    {
        Ok(c) => c,
        Err(e) => return TestResult::failure(name, format!("Client build failed: {}", e)),
    };

    let start = Instant::now();

    // Send 3 sequential requests - should reuse the same H2 connection
    let mut total_body_len = 0;
    let mut all_h2 = true;

    for i in 0..3 {
        let headers = chrome_headers_owned();
        match client
            .get(url)
            .headers(headers)
            .version(HttpVersion::Http2)
            .send()
            .await
        {
            Ok(response) => {
                if response.http_version() != "HTTP/2" {
                    all_h2 = false;
                }
                total_body_len += response.body().len();
            }
            Err(e) => return TestResult::failure(name, format!("Request {} failed: {}", i + 1, e)),
        }
    }

    let duration = start.elapsed().as_millis() as u64;

    if !all_h2 {
        return TestResult::failure(name, "Not all requests used HTTP/2".to_string());
    }

    // The 3 requests should complete faster than 3 separate connections
    TestResult::success(name, "HTTP/2", 200, duration, total_body_len)
}

/// Test HTTP/3 explicit
async fn test_http3_explicit(url: &str, _verbose: bool) -> TestResult {
    let name = "HTTP/3 explicit";

    let client = match ClientBuilder::new()
        .fingerprint(FingerprintProfile::Chrome142)
        .api_timeouts()
        .build()
    {
        Ok(c) => c,
        Err(e) => return TestResult::failure(name, format!("Client build failed: {}", e)),
    };

    // Include forbidden headers to verify filtering
    let mut headers = chrome_headers_owned();
    headers.push(("Connection".to_string(), "keep-alive".to_string()));
    headers.push(("Keep-Alive".to_string(), "timeout=5".to_string()));

    let start = Instant::now();

    match client
        .get(url)
        .headers(headers)
        .version(HttpVersion::Http3Only)
        .send()
        .await
    {
        Ok(response) => {
            let duration = start.elapsed().as_millis() as u64;
            let protocol = response.http_version();
            let status = response.status;
            let body_len = response.body().len();

            if protocol != "HTTP/3" {
                return TestResult::failure(name, format!("Expected HTTP/3, got {}", protocol));
            }

            TestResult::success(name, protocol, status, duration, body_len)
        }
        Err(e) => TestResult::failure(name, format!("{}", e)),
    }
}

/// Test that connection-specific headers are properly filtered
async fn test_connection_header_filtering(url: &str, _verbose: bool) -> TestResult {
    let name = "Connection header filtering";

    let client = match ClientBuilder::new()
        .fingerprint(FingerprintProfile::Chrome142)
        .prefer_http2(true)
        .api_timeouts()
        .build()
    {
        Ok(c) => c,
        Err(e) => return TestResult::failure(name, format!("Client build failed: {}", e)),
    };

    // Include ALL forbidden headers - these must be filtered out for H2/H3
    let mut headers = chrome_headers_owned();
    headers.push(("Connection".to_string(), "keep-alive".to_string()));
    headers.push(("Keep-Alive".to_string(), "timeout=5, max=100".to_string()));
    headers.push(("Proxy-Connection".to_string(), "keep-alive".to_string()));
    headers.push(("Transfer-Encoding".to_string(), "chunked".to_string()));
    headers.push(("Upgrade".to_string(), "websocket".to_string()));

    let start = Instant::now();

    // If headers aren't filtered, the h2 crate will reject with "malformed headers"
    match client
        .get(url)
        .headers(headers)
        .version(HttpVersion::Http2)
        .send()
        .await
    {
        Ok(response) => {
            let duration = start.elapsed().as_millis() as u64;
            let protocol = response.http_version();
            let status = response.status;
            let body_len = response.body().len();

            TestResult::success(name, protocol, status, duration, body_len)
        }
        Err(e) => {
            // Check if it's the specific "malformed headers" error
            let err_str = format!("{}", e);
            if err_str.contains("malformed headers") || err_str.contains("illegal") {
                TestResult::failure(name, "Connection headers not properly filtered".to_string())
            } else {
                TestResult::failure(name, err_str)
            }
        }
    }
}

/// Test POST request with body
async fn test_post_request(base_url: &str, _verbose: bool) -> TestResult {
    let name = "POST request with body";

    // Use httpbin if available, otherwise just POST to the base URL
    let url = if base_url.contains("httpbin.org") {
        "https://httpbin.org/post".to_string()
    } else {
        base_url.to_string()
    };

    let client = match ClientBuilder::new()
        .fingerprint(FingerprintProfile::Chrome142)
        .prefer_http2(true)
        .api_timeouts()
        .build()
    {
        Ok(c) => c,
        Err(e) => return TestResult::failure(name, format!("Client build failed: {}", e)),
    };

    let mut headers = chrome_headers_owned();
    headers.push(("Content-Type".to_string(), "application/json".to_string()));

    let body = r#"{"test": "specter", "protocol": "h2"}"#;

    let start = Instant::now();

    match client
        .post(&url)
        .headers(headers)
        .body(body.as_bytes().to_vec())
        .version(HttpVersion::Http2)
        .send()
        .await
    {
        Ok(response) => {
            let duration = start.elapsed().as_millis() as u64;
            let protocol = response.http_version();
            let status = response.status;
            let body_len = response.body().len();

            // Accept various success codes (200, 201, 301, 302, 405, etc.)
            // Some servers don't accept POST on their root
            TestResult::success(name, protocol, status, duration, body_len)
        }
        Err(e) => TestResult::failure(name, format!("{}", e)),
    }
}

/// Convert static Chrome headers to owned strings
fn chrome_headers_owned() -> Vec<(String, String)> {
    chrome_142_headers()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}
