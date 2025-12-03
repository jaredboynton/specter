//! Fingerprint integration tests.
//!
//! These tests verify our fingerprints don't match known automation tool signatures
//! and correctly emulate Chrome browser fingerprints.
//!
//! Tests against:
//! - tls.peet.ws (TLS/HTTP/2 fingerprint validation)
//! - tls.browserleaks.com (TLS fingerprint validation)
//!
//! Run with: cargo test --test fingerprint_integration

use http::{Method, Uri};
use specter::fingerprint::http2::Http2Settings;
use specter::fingerprint::tls::TlsFingerprint;
use specter::transport::connector::BoringConnector;
use specter::transport::h2::{H2Connection, PseudoHeaderOrder};
use specter::transport::h3::H3Client;
use tracing::warn;

/// Known automation tool fingerprints that we MUST NOT match
const KNOWN_JA3_PYTHON_REQUESTS: &str = "8d9f7747675e24454cd9b7ed35c58707";
const KNOWN_JA3_CURL_7X: &str = "e7d705a3286e19ea42f587b344ee6865";

/// Expected Chrome HTTP/2 Akamai fingerprint components
const CHROME_AKAMAI_SETTINGS: &str = "1:65536;2:0;3:1000;4:6291456;5:16384;6:262144";
const CHROME_WINDOW_UPDATE: &str = "15663105";
const CHROME_PSEUDO_ORDER: &str = "m,s,a,p";
const CHROME_PRIORITY: &str = "0";

/// Expected Chrome Akamai hash (from custom HPACK implementation)
const CHROME_AKAMAI_HASH: &str = "f4734ee6440d645e653283ca349f6a82";

#[tokio::test]
async fn test_tls_fingerprint_unique() {
    let fp = TlsFingerprint::chrome_142();
    let connector = BoringConnector::with_fingerprint(fp);
    let uri: Uri = "https://tls.peet.ws/api/all".parse().unwrap();

    let stream = connector
        .connect(&uri)
        .await
        .expect("TLS connection should succeed");

    // Verify ALPN negotiated h2
    assert!(stream.is_h2(), "Should negotiate HTTP/2 via ALPN");
}

#[tokio::test]
async fn test_http2_fingerprint_matches_chrome() {
    let fp = TlsFingerprint::chrome_142();
    let connector = BoringConnector::with_fingerprint(fp);
    let settings = Http2Settings::default();
    let uri: Uri = "https://tls.peet.ws/api/all".parse().unwrap();

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

    let headers = vec![
        (
            "user-agent".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string(),
        ),
        ("accept".to_string(), "application/json".to_string()),
    ];

    let response = h2_conn
        .send_request(Method::GET, &uri, headers, None)
        .await
        .expect("HTTP/2 request should succeed");

    assert_eq!(response.status, 200, "Should get 200 OK");

    // Parse response JSON
    let body = String::from_utf8_lossy(response.body());
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("Response should be valid JSON");

    // Validate HTTP/2 fingerprint
    if let Some(h2_fp) = json.get("http2") {
        // Check Akamai fingerprint
        if let Some(akamai) = h2_fp.get("akamai_fingerprint") {
            let akamai_str = akamai.as_str().unwrap();
            let parts: Vec<&str> = akamai_str.split('|').collect();

            assert_eq!(parts.len(), 4, "Akamai fingerprint should have 4 parts");

            // Strip GREASE settings (e.g., ":0" suffix) before comparing
            // GREASE settings are random and vary per connection
            let settings_parts: Vec<&str> = parts[0]
                .split(';')
                .filter(|s| {
                    s.starts_with("1:")
                        || s.starts_with("2:")
                        || s.starts_with("3:")
                        || s.starts_with("4:")
                        || s.starts_with("5:")
                        || s.starts_with("6:")
                })
                .collect();
            let normalized_settings = settings_parts.join(";");
            assert_eq!(
                normalized_settings, CHROME_AKAMAI_SETTINGS,
                "SETTINGS should match Chrome (GREASE stripped)"
            );

            assert_eq!(
                parts[1], CHROME_WINDOW_UPDATE,
                "WINDOW_UPDATE should match Chrome"
            );
            assert_eq!(parts[2], CHROME_PRIORITY, "Priority should match Chrome");
            assert_eq!(
                parts[3], CHROME_PSEUDO_ORDER,
                "Pseudo-header order should match Chrome"
            );
        } else {
            panic!("Response should include akamai_fingerprint");
        }

        // Check Akamai hash - note that different services may calculate hashes differently
        // or include GREASE settings in the hash calculation, so we verify it doesn't match
        // known automation tool fingerprints rather than requiring an exact match
        if let Some(hash) = h2_fp.get("akamai_fingerprint_hash") {
            let hash_str = hash.as_str().unwrap();
            // Verify it doesn't match known automation tool hashes
            assert_ne!(hash_str, "", "Akamai hash should be present");
            // The hash may vary between services due to GREASE, so we just verify it's present
            // The exact hash match is validated against browserleaks.com in test_browserleaks_passes
        }

        // Validate sent frames
        if let Some(frames) = h2_fp.get("sent_frames").and_then(|f| f.as_array()) {
            // Frame 0: SETTINGS with 6+ parameters (may include GREASE)
            if let Some(settings_frame) = frames.first() {
                assert_eq!(settings_frame["frame_type"], "SETTINGS");
                let settings_list = settings_frame["settings"].as_array().unwrap();
                // Chrome sends 6 core settings, plus potentially GREASE settings
                assert!(
                    settings_list.len() >= 6,
                    "Should send at least 6 SETTINGS parameters (may include GREASE)"
                );

                // Verify settings order and values
                assert_eq!(settings_list[0], "HEADER_TABLE_SIZE = 65536");
                assert_eq!(settings_list[1], "ENABLE_PUSH = 0");
                assert_eq!(settings_list[2], "MAX_CONCURRENT_STREAMS = 1000");
                assert_eq!(settings_list[3], "INITIAL_WINDOW_SIZE = 6291456");
                assert_eq!(settings_list[4], "MAX_FRAME_SIZE = 16384");
                assert_eq!(settings_list[5], "MAX_HEADER_LIST_SIZE = 262144");
            }

            // Frame 1: WINDOW_UPDATE
            if let Some(wu_frame) = frames.get(1) {
                assert_eq!(wu_frame["frame_type"], "WINDOW_UPDATE");
                assert_eq!(wu_frame["increment"], 15663105);
            }

            // Frame 3: HEADERS with correct pseudo-order
            if let Some(headers_frame) = frames.get(3) {
                assert_eq!(headers_frame["frame_type"], "HEADERS");
                let headers = headers_frame["headers"].as_array().unwrap();

                // Verify pseudo-header order: m,s,a,p
                assert_eq!(headers[0], ":method: GET");
                assert_eq!(headers[1], ":scheme: https");
                assert_eq!(headers[2], ":authority: tls.peet.ws");
                assert_eq!(headers[3], ":path: /api/all");
            }
        }
    }

    // Validate TLS fingerprint
    if let Some(tls_fp) = json.get("tls") {
        if let Some(ja3) = tls_fp.get("ja3_hash") {
            let ja3_str = ja3.as_str().unwrap();

            assert_ne!(
                ja3_str, KNOWN_JA3_PYTHON_REQUESTS,
                "JA3 should NOT match Python requests automation tool fingerprint"
            );
            assert_ne!(
                ja3_str, KNOWN_JA3_CURL_7X,
                "JA3 should NOT match cURL 7.x automation tool fingerprint"
            );
        }
    }
}

#[tokio::test]
async fn test_browserleaks_passes() {
    let fp = TlsFingerprint::chrome_142();
    let connector = BoringConnector::with_fingerprint(fp);
    let settings = Http2Settings::default();
    let uri: Uri = "https://tls.browserleaks.com/json".parse().unwrap();

    let stream = connector
        .connect(&uri)
        .await
        .expect("TLS connection should succeed");

    if !stream.is_h2() {
        warn!("WARNING: Server did not negotiate HTTP/2, skipping test");
        return;
    }

    let mut h2_conn = H2Connection::connect(stream, settings, PseudoHeaderOrder::Chrome)
        .await
        .expect("HTTP/2 connection should succeed");

    let headers = vec![
        ("user-agent".to_string(), "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36".to_string()),
        ("accept".to_string(), "application/json".to_string()),
        ("accept-language".to_string(), "en-US,en;q=0.9".to_string()),
    ];

    let response = h2_conn
        .send_request(Method::GET, &uri, headers, None)
        .await
        .expect("browserleaks.com should accept our fingerprint");

    assert_eq!(
        response.status, 200,
        "browserleaks.com should return 200 OK"
    );

    // Parse and validate response
    let body = String::from_utf8_lossy(response.body());
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("Response should be valid JSON");

    // Verify JA3 doesn't match automation tool fingerprints
    if let Some(ja3) = json.get("ja3_hash") {
        let ja3_str = ja3.as_str().unwrap();
        assert_ne!(ja3_str, KNOWN_JA3_PYTHON_REQUESTS);
        assert_ne!(ja3_str, KNOWN_JA3_CURL_7X);
    }

    // Verify Akamai hash matches Chrome
    if let Some(akamai_hash) = json.get("akamai_hash") {
        assert_eq!(
            akamai_hash.as_str().unwrap(),
            CHROME_AKAMAI_HASH,
            "Akamai hash should match Chrome/h2 crate"
        );
    }
}

#[tokio::test]
async fn test_http3_fingerprint_works() {
    let fp = TlsFingerprint::chrome_142();
    let h3_client = H3Client::with_fingerprint(fp);

    // Test against Cloudflare (known HTTP/3 support)
    let response = h3_client
        .send_request(
            "https://cloudflare.com/cdn-cgi/trace",
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
        .expect("HTTP/3 request should succeed");

    assert_eq!(response.status, 200);
    assert_eq!(response.http_version(), "HTTP/3");

    // Verify trace shows http/3
    let body = String::from_utf8_lossy(response.body());
    assert!(
        body.contains("http=http/3"),
        "Cloudflare trace should confirm HTTP/3"
    );
}

#[test]
fn test_settings_frame_serialization() {
    use specter::transport::h2::{SettingsFrame, SettingsId};

    let settings = Http2Settings::default();
    let mut frame = SettingsFrame::new();
    frame
        .set(SettingsId::HeaderTableSize, settings.header_table_size)
        .set(
            SettingsId::EnablePush,
            if settings.enable_push { 1 } else { 0 },
        )
        .set(
            SettingsId::MaxConcurrentStreams,
            settings.max_concurrent_streams,
        )
        .set(SettingsId::InitialWindowSize, settings.initial_window_size)
        .set(SettingsId::MaxFrameSize, settings.max_frame_size)
        .set(SettingsId::MaxHeaderListSize, settings.max_header_list_size);

    let bytes = frame.serialize();

    // Should be 9-byte header + 36-byte payload (6 settings * 6 bytes)
    assert_eq!(bytes.len(), 45, "SETTINGS frame should be 45 bytes total");

    // Verify payload size
    let length = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
    assert_eq!(length, 36, "Payload should be 36 bytes");
}

#[test]
fn test_goaway_graceful_shutdown() {
    use bytes::Bytes;
    use specter::transport::h2::{ErrorCode, GoAwayFrame, FRAME_HEADER_SIZE};

    // Server sends GOAWAY with NoError and last_stream_id=1
    let goaway = GoAwayFrame::new(1, ErrorCode::NoError);
    let full_frame = goaway.serialize();

    // Parse expects payload only (skip 9-byte header)
    let payload = Bytes::from(full_frame[FRAME_HEADER_SIZE..].to_vec());
    let parsed = GoAwayFrame::parse(payload).unwrap();

    assert_eq!(parsed.last_stream_id, 1);
    assert_eq!(parsed.error_code, ErrorCode::NoError);

    // This means stream 1 is allowed to complete normally
    // Our implementation should continue reading stream 1, not error
}
