//! Streaming HTTP/2 integration tests.
//!
//! These tests verify real streaming capability by connecting to actual
//! streaming endpoints and receiving data incrementally via channels.
//!
//! Run with: cargo test --test streaming_integration

use bytes::Bytes;
use http::{Request, Uri};
use specter::fingerprint::http2::Http2Settings;
use specter::fingerprint::tls::TlsFingerprint;
use specter::transport::connector::BoringConnector;
use specter::transport::h2::{H2Connection, PseudoHeaderOrder};
use std::time::Duration;
use tokio::time::timeout;

/// Test streaming with nghttp2.org's HTTP/2 test server.
/// Uses /httpbin/stream-bytes/N which streams N random bytes.
#[tokio::test]
async fn test_real_streaming_nghttp2() {
    let fp = TlsFingerprint::chrome_142();
    let connector = BoringConnector::with_fingerprint(fp);
    let settings = Http2Settings::default();

    // nghttp2.org supports HTTP/2 and has streaming endpoints
    let uri: Uri = "https://nghttp2.org/httpbin/stream-bytes/4096"
        .parse()
        .unwrap();

    let stream = connector
        .connect(&uri)
        .await
        .expect("TLS connection should succeed");

    if !stream.is_h2() {
        panic!("Server did not negotiate HTTP/2 - cannot test streaming");
    }

    let mut h2_conn = H2Connection::connect(stream, settings, PseudoHeaderOrder::Chrome)
        .await
        .expect("HTTP/2 connection should succeed");

    // Build streaming request - do NOT include pseudo-headers, H2 handles those
    let request = Request::builder()
        .method("GET")
        .uri(&uri)
        .header(
            "user-agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        )
        .header("accept", "*/*")
        .body(Bytes::new())
        .expect("Failed to build request");

    // Send streaming request
    let (response, mut rx) = h2_conn
        .send_request_streaming(request)
        .await
        .expect("Streaming request should succeed");

    assert_eq!(response.status(), 200, "Should get 200 OK");

    // Spawn reader task
    let reader_handle = tokio::spawn(async move {
        let mut bytes_received = 0;
        let mut chunks = 0;

        while let Some(result) = rx.recv().await {
            match result {
                Ok(chunk) => {
                    bytes_received += chunk.len();
                    chunks += 1;
                }
                Err(e) => {
                    panic!("Stream error: {}", e);
                }
            }
        }

        (bytes_received, chunks)
    });

    // Drive the connection to read frames
    let driver_handle = tokio::spawn(async move {
        loop {
            match h2_conn.read_streaming_frames().await {
                Ok(true) => continue,
                Ok(false) => break, // Stream ended
                Err(e) => {
                    // Connection closed or error - this is expected when stream ends
                    tracing::debug!("Stream reader ended: {}", e);
                    break;
                }
            }
        }
    });

    // Wait for both tasks with timeout
    let (total_bytes, chunk_count) = timeout(Duration::from_secs(30), async {
        // Wait for driver to finish (which signals stream end)
        let _ = driver_handle.await;
        // Then get results from reader
        reader_handle.await.expect("Reader task should complete")
    })
    .await
    .expect("Streaming should complete within 30 seconds");

    // Verify we received data in chunks
    assert!(total_bytes > 0, "Should have received some bytes");
    assert!(
        chunk_count >= 1,
        "Should have received at least 1 chunk (got {} chunks, {} bytes)",
        chunk_count,
        total_bytes
    );

    tracing::info!(
        "Streaming test passed: received {} bytes in {} chunks",
        total_bytes,
        chunk_count
    );
}

/// Test streaming with Cloudflare's HTTP/2 SSE-style endpoint.
#[tokio::test]
async fn test_real_streaming_cloudflare_trace() {
    let fp = TlsFingerprint::chrome_142();
    let connector = BoringConnector::with_fingerprint(fp);
    let settings = Http2Settings::default();

    // Cloudflare's trace endpoint (returns small response, but validates H2 streaming works)
    let uri: Uri = "https://cloudflare.com/cdn-cgi/trace".parse().unwrap();

    let stream = connector
        .connect(&uri)
        .await
        .expect("TLS connection should succeed");

    if !stream.is_h2() {
        // Some Cloudflare endpoints may not negotiate H2, skip test
        tracing::info!("Cloudflare did not negotiate HTTP/2, skipping streaming test");
        return;
    }

    let mut h2_conn = H2Connection::connect(stream, settings, PseudoHeaderOrder::Chrome)
        .await
        .expect("HTTP/2 connection should succeed");

    // Build request without pseudo-headers
    let request = Request::builder()
        .method("GET")
        .uri(&uri)
        .header(
            "user-agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        )
        .header("accept", "*/*")
        .body(Bytes::new())
        .expect("Failed to build request");

    let (response, mut rx) = h2_conn
        .send_request_streaming(request)
        .await
        .expect("Streaming request should succeed");

    assert_eq!(response.status(), 200, "Should get 200 OK");

    // Collect response body via streaming
    let reader_handle = tokio::spawn(async move {
        let mut body = Vec::new();
        while let Some(result) = rx.recv().await {
            match result {
                Ok(chunk) => body.extend_from_slice(&chunk),
                Err(e) => panic!("Stream error: {}", e),
            }
        }
        body
    });

    // Drive connection
    let driver_handle = tokio::spawn(async move {
        loop {
            match h2_conn.read_streaming_frames().await {
                Ok(true) => continue,
                Ok(false) => break,
                Err(_) => break,
            }
        }
    });

    let body = timeout(Duration::from_secs(10), async {
        let _ = driver_handle.await;
        reader_handle.await.expect("Reader should complete")
    })
    .await
    .expect("Should complete within 10 seconds");

    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("fl=") || body_str.contains("h="),
        "Cloudflare trace should contain connection info"
    );

    tracing::info!("Cloudflare streaming test passed: {} bytes", body.len());
}

/// Test streaming larger response to verify chunking behavior.
#[tokio::test]
async fn test_streaming_larger_response() {
    let fp = TlsFingerprint::chrome_142();
    let connector = BoringConnector::with_fingerprint(fp);
    let settings = Http2Settings::default();

    // Request 64KB of random bytes - should definitely chunk
    let uri: Uri = "https://nghttp2.org/httpbin/stream-bytes/65536"
        .parse()
        .unwrap();

    let stream = connector
        .connect(&uri)
        .await
        .expect("TLS connection should succeed");

    if !stream.is_h2() {
        panic!("Server did not negotiate HTTP/2");
    }

    let mut h2_conn = H2Connection::connect(stream, settings, PseudoHeaderOrder::Chrome)
        .await
        .expect("HTTP/2 connection should succeed");

    let request = Request::builder()
        .method("GET")
        .uri(&uri)
        .header(
            "user-agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        )
        .header("accept", "*/*")
        .body(Bytes::new())
        .expect("Failed to build request");

    let (response, mut rx) = h2_conn
        .send_request_streaming(request)
        .await
        .expect("Streaming request should succeed");

    assert_eq!(response.status(), 200);

    // Track chunk sizes to verify we're actually streaming
    let reader_handle = tokio::spawn(async move {
        let mut chunk_sizes: Vec<usize> = Vec::new();
        while let Some(result) = rx.recv().await {
            match result {
                Ok(chunk) => chunk_sizes.push(chunk.len()),
                Err(e) => panic!("Stream error: {}", e),
            }
        }
        chunk_sizes
    });

    let driver_handle = tokio::spawn(async move {
        loop {
            match h2_conn.read_streaming_frames().await {
                Ok(true) => continue,
                Ok(false) => break,
                Err(_) => break,
            }
        }
    });

    let chunk_sizes = timeout(Duration::from_secs(60), async {
        let _ = driver_handle.await;
        reader_handle.await.expect("Reader should complete")
    })
    .await
    .expect("Should complete within 60 seconds");

    let total_bytes: usize = chunk_sizes.iter().sum();
    let chunk_count = chunk_sizes.len();

    // For 64KB, we expect multiple chunks (HTTP/2 max frame size is typically 16KB)
    assert!(
        chunk_count >= 2,
        "64KB response should arrive in multiple chunks (got {} chunks)",
        chunk_count
    );
    assert!(
        total_bytes >= 60000,
        "Should receive at least 60KB (got {} bytes)",
        total_bytes
    );

    tracing::info!(
        "Large streaming test passed: {} bytes in {} chunks",
        total_bytes,
        chunk_count
    );
    tracing::debug!("Chunk sizes: {:?}", chunk_sizes);
}

/// Test that streaming API correctly handles response headers.
#[tokio::test]
async fn test_streaming_headers_available_immediately() {
    let fp = TlsFingerprint::chrome_142();
    let connector = BoringConnector::with_fingerprint(fp);
    let settings = Http2Settings::default();

    let uri: Uri = "https://nghttp2.org/httpbin/headers".parse().unwrap();

    let stream = connector
        .connect(&uri)
        .await
        .expect("TLS connection should succeed");

    if !stream.is_h2() {
        panic!("Server did not negotiate HTTP/2");
    }

    let mut h2_conn = H2Connection::connect(stream, settings, PseudoHeaderOrder::Chrome)
        .await
        .expect("HTTP/2 connection should succeed");

    let request = Request::builder()
        .method("GET")
        .uri(&uri)
        .header("user-agent", "specter/test")
        .header("accept", "application/json")
        .header("x-custom-header", "test-value")
        .body(Bytes::new())
        .expect("Failed to build request");

    let (response, mut rx) = h2_conn
        .send_request_streaming(request)
        .await
        .expect("Streaming request should succeed");

    // Headers should be available immediately (before body streams)
    assert_eq!(response.status(), 200, "Should get 200 OK");

    // Check content-type header is present
    let content_type = response
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap_or(""));
    assert!(
        content_type.is_some(),
        "Content-Type header should be present"
    );

    // Now collect body
    let reader_handle = tokio::spawn(async move {
        let mut body = Vec::new();
        while let Some(result) = rx.recv().await {
            if let Ok(chunk) = result {
                body.extend_from_slice(&chunk);
            }
        }
        body
    });

    let driver_handle = tokio::spawn(async move {
        loop {
            match h2_conn.read_streaming_frames().await {
                Ok(true) => continue,
                Ok(false) => break,
                Err(_) => break,
            }
        }
    });

    let body = timeout(Duration::from_secs(10), async {
        let _ = driver_handle.await;
        reader_handle.await.expect("Reader should complete")
    })
    .await
    .expect("Should complete within 10 seconds");

    // Verify response contains our headers echoed back
    let body_str = String::from_utf8_lossy(&body);
    let json: serde_json::Value = serde_json::from_str(&body_str).expect("Should be valid JSON");

    if let Some(headers) = json.get("headers") {
        assert!(
            headers.get("X-Custom-Header").is_some() || headers.get("x-custom-header").is_some(),
            "Custom header should be echoed back"
        );
    }

    tracing::info!("Headers streaming test passed");
}
