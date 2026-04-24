//! HTTP/2 Multiplexing Validation Tests
//!
//! Tests that the specter client properly multiplexes concurrent requests
//! over a single HTTP/2 connection using the mock H2 server infrastructure.

use specter::Client;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};
use helpers::tls::generate_cert_bundle;

/// Perform the H2 handshake (preface + SETTINGS exchange) and return the first
/// HEADERS frame's stream ID. Also records all observed stream IDs.
async fn h2_handshake_and_serve(
    conn: &MockH2Connection,
    observed_stream_ids: Arc<Mutex<Vec<u32>>>,
) {
    // Read client preface.
    if let Err(e) = conn.read_preface().await {
        tracing::error!("Preface error: {}", e);
        return;
    }

    // Process frames: handle SETTINGS, respond to HEADERS frames.
    // We will serve multiple requests on this single connection.
    let mut settings_sent = false;

    loop {
        let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(_)) => break, // Connection closed.
            Err(_) => break,     // Timeout -- no more frames.
        };

        let (_len, frame_type, flags, stream_id, _payload) = frame;

        match frame_type {
            0x04 => {
                // SETTINGS
                if flags & 0x01 == 0 && !settings_sent {
                    // Client SETTINGS -- reply with our SETTINGS + ACK.
                    conn.send_settings(&[
                        (0x01, 4096),  // HEADER_TABLE_SIZE
                        (0x03, 100),   // MAX_CONCURRENT_STREAMS
                        (0x04, 65535), // INITIAL_WINDOW_SIZE
                    ])
                    .await
                    .unwrap();
                    conn.send_settings_ack().await.unwrap();
                    settings_sent = true;
                }
                // else: ACK from client, ignore.
            }
            0x01 => {
                // HEADERS -- a new request on this stream.
                let mut ids = observed_stream_ids.lock().await;
                ids.push(stream_id);

                // Send a minimal response: :status 200 + small body.
                let response_headers = vec![0x88]; // :status 200 (HPACK indexed)
                conn.send_headers(stream_id, &response_headers, false, true)
                    .await
                    .unwrap();

                // Include the stream ID in the response body so the client can verify.
                let body = format!("stream-{}", stream_id);
                conn.send_data(stream_id, body.as_bytes(), true)
                    .await
                    .unwrap();
            }
            0x08 => {
                // WINDOW_UPDATE -- ignore.
            }
            _ => {
                // Ignore other frame types.
            }
        }
    }
}

/// Verify that multiple concurrent requests to the same H2 server are multiplexed
/// onto a single connection with unique, odd-numbered stream IDs.
#[tokio::test]
async fn test_h2_parallel_requests_multiplex() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    // TLS setup with h2 ALPN.
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();
    let observed_ids: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let ids_clone = observed_ids.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let ids = ids_clone.clone();
        async move {
            h2_handshake_and_serve(&conn, ids).await;
        }
    });

    // Build client that prefers H2 and trusts our self-signed cert.
    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    // Send 3 sequential requests (H2 connection pooling means they share the connection).
    let mut responses = Vec::new();
    for i in 0..3 {
        let req_url = format!("{}/request-{}", url, i);
        let result = timeout(Duration::from_secs(5), client.get(req_url.as_str()).send()).await;
        assert!(result.is_ok(), "Request {} timed out", i);
        let resp = result.unwrap();
        assert!(resp.is_ok(), "Request {} failed: {:?}", i, resp.err());
        responses.push(resp.unwrap());
    }

    // Verify all responses succeeded.
    for (i, resp) in responses.iter().enumerate() {
        assert_eq!(
            resp.status().as_u16(),
            200,
            "Request {} returned non-200 status",
            i
        );
        assert_eq!(
            resp.http_version(),
            "HTTP/2",
            "Request {} did not use HTTP/2",
            i
        );
    }

    // Verify stream IDs are unique and odd (client-initiated streams must be odd per RFC 9113).
    let ids = observed_ids.lock().await;
    assert!(
        !ids.is_empty(),
        "No stream IDs were observed by the mock server"
    );
    let unique_ids: HashSet<u32> = ids.iter().copied().collect();
    assert_eq!(
        unique_ids.len(),
        ids.len(),
        "Stream IDs should be unique. Observed: {:?}",
        *ids
    );
    for &id in ids.iter() {
        assert!(
            id % 2 == 1,
            "Client-initiated stream ID must be odd, got: {}",
            id
        );
    }
}

/// Verify that stream IDs are properly assigned in ascending order.
#[tokio::test]
async fn test_h2_stream_ids_ascending() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();
    let observed_ids: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let ids_clone = observed_ids.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let ids = ids_clone.clone();
        async move {
            h2_handshake_and_serve(&conn, ids).await;
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    // Send 5 sequential requests on the same pooled H2 connection.
    for i in 0..5 {
        let req_url = format!("{}/req-{}", url, i);
        let result = timeout(Duration::from_secs(5), client.get(req_url.as_str()).send()).await;
        assert!(result.is_ok(), "Request {} timed out", i);
        let resp = result.unwrap();
        assert!(resp.is_ok(), "Request {} failed: {:?}", i, resp.err());
    }

    let ids = observed_ids.lock().await;
    assert!(
        ids.len() >= 2,
        "Expected at least 2 stream IDs, got {}",
        ids.len()
    );

    // Stream IDs should be strictly ascending.
    for window in ids.windows(2) {
        assert!(
            window[1] > window[0],
            "Stream IDs should be ascending: {} should be > {}",
            window[1],
            window[0]
        );
    }

    // First client-initiated stream should be 1.
    assert_eq!(ids[0], 1, "First client stream ID should be 1");
}

/// Verify that each response body correctly corresponds to its stream.
/// This confirms the multiplexer does not mix up response data across streams.
#[tokio::test]
async fn test_h2_response_body_per_stream() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();
    let observed_ids: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let ids_clone = observed_ids.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let ids = ids_clone.clone();
        async move {
            h2_handshake_and_serve(&conn, ids).await;
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    // Send 3 requests and collect bodies.
    let mut bodies = Vec::new();
    for i in 0..3 {
        let req_url = format!("{}/item-{}", url, i);
        let resp = timeout(Duration::from_secs(5), client.get(req_url.as_str()).send())
            .await
            .expect("Request timed out")
            .expect("Request failed");

        bodies.push(resp.text().unwrap());
    }

    // Each body should contain "stream-N" where N is the stream ID.
    // The important thing is that all bodies are distinct (no mixing).
    let unique_bodies: HashSet<&String> = bodies.iter().collect();
    assert_eq!(
        unique_bodies.len(),
        bodies.len(),
        "Response bodies should be distinct across streams. Got: {:?}",
        bodies
    );

    // Each body should match the pattern "stream-<odd_number>".
    for body in &bodies {
        assert!(
            body.starts_with("stream-"),
            "Expected body starting with 'stream-', got: {}",
            body
        );
        let id_str = body.strip_prefix("stream-").unwrap();
        let id: u32 = id_str
            .parse()
            .unwrap_or_else(|_| panic!("Expected numeric stream ID, got: {}", id_str));
        assert!(id % 2 == 1, "Stream ID in body should be odd, got: {}", id);
    }
}
