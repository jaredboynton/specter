//! HTTP/2 response trailer surfacing tests (gRPC Phase 1).
//!
//! Verifies the three-state `Response::trailers()` contract against a local
//! mock H2 server bound to `127.0.0.1:0`:
//!   1. real trailer HEADERS frame  -> `Ok(Some(headers))`
//!   2. clean end, no trailer frame -> `Ok(None)`
//!   3. RST_STREAM before clean end -> `Err(_)`
//!
//! All three requests carry `te: trailers` so the trailer side channel is
//! allocated on the streaming path. No fixed sleeps, no fixed ports.

use std::time::Duration;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};
use helpers::tls::generate_cert_bundle;
use specter::transport::h2::hpack_impl::Encoder;
use specter::Client;

/// Build an ALPN-h2 TLS acceptor and a client trusting its CA.
fn h2_tls_setup() -> (boring::ssl::SslAcceptor, specter::Client) {
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

/// Drain the streaming body to end, ignoring chunk contents.
async fn drain_body(response: &mut specter::Response) {
    while let Some(frame) = response.body_mut().frame().await {
        // Surface a transport error (case 3 may reset mid-body); the trailers()
        // assertion is what distinguishes the cases.
        let _ = frame;
    }
}

#[tokio::test]
async fn trailers_real_frame_surfaces_grpc_status() {
    let (acceptor, client) = h2_tls_setup();
    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, move |conn: MockH2Connection| async move {
        conn.read_preface().await.unwrap();
        let mut settings_sent = false;
        let mut encoder = Encoder::new();
        loop {
            let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                Ok(Ok(f)) => f,
                _ => break,
            };
            let (_len, frame_type, flags, stream_id, _payload) = frame;
            match frame_type {
                0x04 if flags & 0x01 == 0 && !settings_sent => {
                    conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                        .await
                        .unwrap();
                    conn.send_settings_ack().await.unwrap();
                    settings_sent = true;
                }
                0x01 => {
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
                    conn.send_data(stream_id, b"\x00\x00\x00\x00\x00", false)
                        .await
                        .unwrap();
                    // Trailing HEADERS frame (no pseudo-headers) with END_STREAM.
                    let trailers = encoder.encode(&[
                        (b"grpc-status".as_slice(), b"0".as_slice()),
                        (b"grpc-message".as_slice(), b"ok".as_slice()),
                    ]);
                    conn.send_headers(stream_id, &trailers, true, true)
                        .await
                        .unwrap();
                }
                _ => {}
            }
        }
    });

    let req_url = format!("{}/pkg.Svc/Method", url);
    let mut response = timeout(
        Duration::from_secs(5),
        client
            .get(&req_url)
            .header("te", "trailers")
            .send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response.status().as_u16(), 200);
    drain_body(&mut response).await;

    let trailers = response
        .trailers()
        .await
        .expect("trailers() must not error on a clean trailer frame")
        .expect("a real trailer frame must yield Some(headers)");
    assert_eq!(trailers.get("grpc-status"), Some("0"));
    assert_eq!(trailers.get("grpc-message"), Some("ok"));
}

#[tokio::test]
async fn trailers_clean_end_without_frame_is_none() {
    let (acceptor, client) = h2_tls_setup();
    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, move |conn: MockH2Connection| async move {
        conn.read_preface().await.unwrap();
        let mut settings_sent = false;
        let mut encoder = Encoder::new();
        loop {
            let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                Ok(Ok(f)) => f,
                _ => break,
            };
            let (_len, frame_type, flags, stream_id, _payload) = frame;
            match frame_type {
                0x04 if flags & 0x01 == 0 && !settings_sent => {
                    conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                        .await
                        .unwrap();
                    conn.send_settings_ack().await.unwrap();
                    settings_sent = true;
                }
                0x01 => {
                    let response_headers =
                        encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                    conn.send_headers(stream_id, &response_headers, false, true)
                        .await
                        .unwrap();
                    // DATA with END_STREAM: clean end, no trailer HEADERS frame.
                    conn.send_data(stream_id, b"payload-bytes", true)
                        .await
                        .unwrap();
                }
                _ => {}
            }
        }
    });

    let req_url = format!("{}/pkg.Svc/Method", url);
    let mut response = timeout(
        Duration::from_secs(5),
        client
            .get(&req_url)
            .header("te", "trailers")
            .send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response.status().as_u16(), 200);
    drain_body(&mut response).await;

    let trailers = timeout(Duration::from_secs(5), response.trailers())
        .await
        .expect("trailers() must resolve after a clean trailer-less end")
        .expect("trailers() must not error on a clean end");
    assert!(
        trailers.is_none(),
        "clean trailer-less end must map to Ok(None)"
    );
}

#[tokio::test]
async fn trailers_after_reset_is_err() {
    let (acceptor, client) = h2_tls_setup();
    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, move |conn: MockH2Connection| async move {
        conn.read_preface().await.unwrap();
        let mut settings_sent = false;
        let mut encoder = Encoder::new();
        loop {
            let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                Ok(Ok(f)) => f,
                _ => break,
            };
            let (_len, frame_type, flags, stream_id, _payload) = frame;
            match frame_type {
                0x04 if flags & 0x01 == 0 && !settings_sent => {
                    conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                        .await
                        .unwrap();
                    conn.send_settings_ack().await.unwrap();
                    settings_sent = true;
                }
                0x01 => {
                    let response_headers =
                        encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                    conn.send_headers(stream_id, &response_headers, false, true)
                        .await
                        .unwrap();
                    conn.send_data(stream_id, b"partial", false).await.unwrap();
                    // Reset the stream before any clean end (5 = INTERNAL_ERROR).
                    conn.send_rst_stream(stream_id, 2).await.unwrap();
                }
                _ => {}
            }
        }
    });

    let req_url = format!("{}/pkg.Svc/Method", url);
    let mut response = timeout(
        Duration::from_secs(5),
        client
            .get(&req_url)
            .header("te", "trailers")
            .send_streaming(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(response.status().as_u16(), 200);
    // Drain the body; the reset may surface here as a body error, which is fine.
    drain_body(&mut response).await;

    let result = timeout(Duration::from_secs(5), response.trailers())
        .await
        .expect("trailers() must resolve after a stream reset");
    assert!(
        result.is_err(),
        "a stream reset must surface as Err, distinct from Ok(None)"
    );
}
