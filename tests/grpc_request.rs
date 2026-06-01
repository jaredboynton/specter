//! gRPC request construction tests (gRPC Phase 3).
//!
//! Verifies that `specter::grpc::grpc_request` produces a fingerprint-safe gRPC
//! HTTP/2 request against a local mock H2 server bound to `127.0.0.1:0`:
//!   - `:method` is `POST`
//!   - `:path` is the URL path (`/pkg.Svc/Method`)
//!   - the four pseudo-headers lead in the active profile's order
//!     (`:method`, `:scheme`, `:authority`, `:path` for the default Chrome profile)
//!   - regular headers include `content-type: application/grpc+proto` and
//!     `te: trailers` in caller order; `grpc-encoding: gzip` appears only when the
//!     caller requests gzip, and after `te`.
//!
//! No fixed sleeps, no fixed ports. The mock helper's `read_decoded_headers()`
//! already surfaces the HPACK-decoded request headers in wire order, so the
//! helper is untouched (keeping the Phase 1 trailers tests unaffected).
#![cfg(feature = "grpc")]

use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h2_server::{DecodedHeadersFrame, MockH2Connection, MockH2Server};
use helpers::tls::generate_cert_bundle;
use specter::grpc::{grpc_request, GrpcEncoding};
use specter::transport::h2::hpack_impl::Encoder;
use specter::Client;

/// Build an ALPN-h2 TLS acceptor and a client trusting its CA (default Chrome
/// fingerprint profile).
fn h2_tls_setup() -> (boring::ssl::SslAcceptor, Client) {
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();
    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();
    (acceptor, client)
}

/// Index of a regular header by name (case-insensitive) in wire order.
fn index_of(frame: &DecodedHeadersFrame, name: &str) -> Option<usize> {
    frame
        .headers
        .iter()
        .position(|(key, _)| key.eq_ignore_ascii_case(name))
}

/// Assert the pseudo-header block leads in the default Chrome order with the
/// expected method and path, and returns nothing (panics on mismatch).
fn assert_pseudo_order_and_target(frame: &DecodedHeadersFrame, expected_path: &str) {
    assert_eq!(
        frame.headers[0].0, ":method",
        "first pseudo must be :method; got {:?}",
        frame.headers
    );
    assert_eq!(frame.headers[0].1, "POST", "gRPC request must be POST");
    assert_eq!(frame.headers[1].0, ":scheme");
    assert_eq!(frame.headers[2].0, ":authority");
    assert_eq!(frame.headers[3].0, ":path");
    assert_eq!(
        frame.headers[3].1, expected_path,
        ":path must be the service/method path"
    );
}

/// Run one gRPC request through the mock server and return the decoded inbound
/// HEADERS frame. The handler completes the response (200 + END_STREAM) so the
/// client future resolves; no sleeps are used.
async fn capture_request_headers(encoding: GrpcEncoding, path: &str) -> DecodedHeadersFrame {
    let (acceptor, client) = h2_tls_setup();
    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let (tx, mut rx) = mpsc::channel::<DecodedHeadersFrame>(1);

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let tx = tx.clone();
        async move {
            conn.read_preface().await.unwrap();
            // Server preface: SETTINGS + ACK so the client releases its HEADERS.
            conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                .await
                .unwrap();
            conn.send_settings_ack().await.unwrap();

            // Capture the request HEADERS frame (skips SETTINGS/WINDOW_UPDATE/PRIORITY).
            let decoded = match conn.read_decoded_headers().await {
                Ok(d) => d,
                Err(_) => return,
            };
            let stream_id = decoded.stream_id;
            let _ = tx.send(decoded).await;

            // Complete the response so the client request resolves cleanly.
            let mut encoder = Encoder::new();
            let response_headers = encoder.encode(&[
                (b":status".as_slice(), b"200".as_slice()),
                (
                    b"content-type".as_slice(),
                    b"application/grpc+proto".as_slice(),
                ),
            ]);
            conn.send_headers(stream_id, &response_headers, false, true)
                .await
                .unwrap();
            // Empty gRPC frame then END_STREAM via a trailers HEADERS frame.
            conn.send_data(stream_id, b"\x00\x00\x00\x00\x00", false)
                .await
                .unwrap();
            let trailers = encoder.encode(&[(b"grpc-status".as_slice(), b"0".as_slice())]);
            conn.send_headers(stream_id, &trailers, true, true)
                .await
                .unwrap();
        }
    });

    let req_url = format!("{}{}", url, path);
    // This test asserts the constructor's method/path/header shape; the caller
    // is responsible for the body, so none is attached here (matching the
    // headers-only contract and the Phase 1 trailers fixture pattern).
    let send = grpc_request(&client, &req_url, encoding).send_streaming();

    let mut response = timeout(Duration::from_secs(5), send)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    // Drain the body so the request fully completes.
    while let Some(frame) = response.body_mut().frame().await {
        let _ = frame;
    }

    timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("server must observe the request HEADERS frame")
        .expect("headers channel must yield the decoded frame")
}

#[tokio::test]
async fn grpc_request_identity_shape() {
    let path = "/pkg.Svc/Method";
    let frame = capture_request_headers(GrpcEncoding::Identity, path).await;

    // Method + path + pseudo order match the active (Chrome) profile.
    assert_pseudo_order_and_target(&frame, path);

    // Required regular headers present with exact values.
    assert_eq!(
        frame.header("content-type"),
        Some("application/grpc+proto"),
        "decoded: {:?}",
        frame.headers
    );
    assert_eq!(frame.header("te"), Some("trailers"));

    // Caller order: content-type before te (relative, robust against any
    // profile-synthesized regular headers preceding them).
    let ct = index_of(&frame, "content-type").expect("content-type present");
    let te = index_of(&frame, "te").expect("te present");
    assert!(
        ct < te,
        "content-type must precede te; decoded: {:?}",
        frame.headers
    );

    // Identity encoding must NOT emit grpc-encoding.
    assert!(
        !frame.has_header("grpc-encoding"),
        "identity request must not carry grpc-encoding; decoded: {:?}",
        frame.headers
    );
}

#[tokio::test]
async fn grpc_request_gzip_shape() {
    let path = "/helloworld.Greeter/SayHello";
    let frame = capture_request_headers(GrpcEncoding::Gzip, path).await;

    assert_pseudo_order_and_target(&frame, path);

    assert_eq!(frame.header("content-type"), Some("application/grpc+proto"));
    assert_eq!(frame.header("te"), Some("trailers"));
    assert_eq!(frame.header("grpc-encoding"), Some("gzip"));

    // Caller order: content-type < te < grpc-encoding.
    let ct = index_of(&frame, "content-type").expect("content-type present");
    let te = index_of(&frame, "te").expect("te present");
    let enc = index_of(&frame, "grpc-encoding").expect("grpc-encoding present");
    assert!(
        ct < te && te < enc,
        "caller header order must be content-type < te < grpc-encoding; decoded: {:?}",
        frame.headers
    );
}
