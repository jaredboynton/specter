use specter::transport::h2::{HpackDecoder, HpackEncoder};

fn decode(block: &[u8]) -> Vec<(String, String)> {
    let mut decoder = HpackDecoder::new();
    decoder.decode(block).expect("valid RFC 8441 header block")
}

#[test]
fn rfc8441_extended_connect_encodes_required_pseudo_headers_first() {
    let mut encoder = HpackEncoder::chrome();
    let block = encoder
        .encode_extended_connect_websocket(
            "example.com",
            "https",
            "/chat",
            &[
                ("Origin".to_string(), "https://example.com".to_string()),
                (
                    "Sec-WebSocket-Protocol".to_string(),
                    "chat, superchat".to_string(),
                ),
            ],
        )
        .expect("valid extended CONNECT headers");

    let headers = decode(&block);
    assert_eq!(
        &headers[..5],
        [
            (":method".to_string(), "CONNECT".to_string()),
            (":protocol".to_string(), "websocket".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":path".to_string(), "/chat".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ]
    );
    assert_eq!(
        headers[5..],
        [
            ("origin".to_string(), "https://example.com".to_string()),
            (
                "sec-websocket-protocol".to_string(),
                "chat, superchat".to_string(),
            ),
        ]
    );
}

#[test]
fn rfc8441_extended_connect_rejects_h1_websocket_headers() {
    let forbidden = [
        "connection",
        "upgrade",
        "host",
        "sec-websocket-key",
        "sec-websocket-accept",
    ];

    for name in forbidden {
        let mut encoder = HpackEncoder::chrome();
        let err = encoder
            .encode_extended_connect_websocket(
                "example.com",
                "https",
                "/chat",
                &[(name.to_string(), "bad".to_string())],
            )
            .expect_err("forbidden RFC 8441 header should be rejected");

        assert!(
            err.contains(name),
            "error {err:?} should identify rejected header {name}"
        );
    }
}

#[test]
fn rfc8441_extended_connect_rejects_user_pseudo_headers() {
    let mut encoder = HpackEncoder::chrome();
    let err = encoder
        .encode_extended_connect_websocket(
            "example.com",
            "https",
            "/chat",
            &[(":protocol".to_string(), "not-websocket".to_string())],
        )
        .expect_err("user pseudo headers must not be accepted");

    assert!(err.contains(":protocol"));
}

#[test]
fn rfc8441_extended_connect_rejects_extensions_until_shared_codec_supports_them() {
    let mut encoder = HpackEncoder::chrome();
    let err = encoder
        .encode_extended_connect_websocket(
            "example.com",
            "https",
            "/chat",
            &[(
                "Sec-WebSocket-Extensions".to_string(),
                "permessage-deflate".to_string(),
            )],
        )
        .expect_err("extensions require shared RFC 6455 extension support");

    assert!(err.contains("sec-websocket-extensions"));
}

#[test]
fn rfc8441_extended_connect_allows_version_and_origin_headers_lowercased() {
    let mut encoder = HpackEncoder::chrome();
    let block = encoder
        .encode_extended_connect_websocket(
            "example.com",
            "https",
            "/chat",
            &[
                ("Origin".to_string(), "https://app.example".to_string()),
                ("Sec-WebSocket-Version".to_string(), "13".to_string()),
            ],
        )
        .expect("allowed WebSocket metadata should encode");

    let headers = decode(&block);

    assert!(headers.contains(&("origin".to_string(), "https://app.example".to_string())));
    assert!(headers.contains(&("sec-websocket-version".to_string(), "13".to_string())));
    assert!(!headers.iter().any(|(name, _)| name == "Origin"));
    assert!(!headers
        .iter()
        .any(|(name, _)| name == "Sec-WebSocket-Version"));
}
