//! RFC 8441 public client API tests.
//!
//! These tests define the intended API shape for client-side WebSockets over
//! HTTP/2 Extended CONNECT. They should fail to compile until the API exists.

use specter::{Client, Error};
use std::time::Duration;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};
use helpers::tls::generate_cert_bundle;

async fn read_client_settings_and_send_rfc8441_enable(conn: &MockH2Connection) {
    conn.read_preface().await.unwrap();
    let (_, frame_type, flags, _, _) = conn.read_frame().await.unwrap();
    assert_eq!(frame_type, 0x04, "client must send SETTINGS first");
    assert_eq!(flags & 0x01, 0, "first client SETTINGS must not be ACK");
    conn.send_settings(&[(0x08, 1)]).await.unwrap();
    conn.send_settings_ack().await.unwrap();
}

async fn accept_one_rfc8441_tunnel(
    conn: MockH2Connection,
    scheme: &'static str,
    authority: String,
) {
    read_client_settings_and_send_rfc8441_enable(&conn).await;

    let headers = timeout(Duration::from_secs(5), conn.read_decoded_headers())
        .await
        .expect("timed out waiting for RFC 8441 CONNECT")
        .unwrap();

    headers.assert_rfc8441_websocket_connect(&authority, scheme, "/chat?room=one");
    conn.send_headers(headers.stream_id, &[0x88], false, true)
        .await
        .unwrap();
}

fn h2_tls_acceptor() -> (boring::ssl::SslAcceptor, Vec<u8>) {
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    (builder.build(), ca_cert)
}

fn h1_tls_acceptor() -> (boring::ssl::SslAcceptor, Vec<u8>) {
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x08http/1.1", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    (builder.build(), ca_cert)
}

#[tokio::test]
async fn rfc8441_wss_with_h2_alpn_opens() {
    let (acceptor, ca_cert) = h2_tls_acceptor();
    let server = MockH2Server::new().await.unwrap();
    let url = format!("{}/chat?room=one", server.url_tls()).replace("https://", "wss://");
    let authority = format!("127.0.0.1:{}", server.port());

    server.start_tls(acceptor, move |conn| {
        accept_one_rfc8441_tunnel(conn, "https", authority.clone())
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    timeout(Duration::from_secs(5), client.websocket_h2(&url).open())
        .await
        .expect("wss RFC 8441 open timed out")
        .expect("wss with ALPN h2 should open");
}

#[tokio::test]
async fn rfc8441_ws_with_prior_knowledge_opens() {
    let server = MockH2Server::new().await.unwrap();
    let url = format!("ws://127.0.0.1:{}/chat?room=one", server.port());
    let authority = format!("127.0.0.1:{}", server.port());

    server.start(move |conn| accept_one_rfc8441_tunnel(conn, "http", authority.clone()));

    let client = Client::builder()
        .prefer_http2(true)
        .http2_prior_knowledge(true)
        .build()
        .unwrap();

    timeout(Duration::from_secs(5), client.websocket_h2(&url).open())
        .await
        .expect("ws prior-knowledge RFC 8441 open timed out")
        .expect("ws with explicit H2 prior knowledge should open");
}

#[tokio::test]
async fn rfc8441_ws_without_prior_knowledge_is_rejected_before_h2_bytes() {
    let server = MockH2Server::new().await.unwrap();
    let url = format!("ws://127.0.0.1:{}/chat?room=one", server.port());

    server.start(|conn| async move {
        let read = timeout(Duration::from_millis(300), conn.read_frame()).await;
        assert!(
            read.is_err(),
            "ws without prior knowledge must fail before sending HTTP/2 frames"
        );
    });

    let client = Client::builder().prefer_http2(true).build().unwrap();

    let err = match client.websocket_h2(&url).open().await {
        Ok(_) => panic!("ws without H2 prior knowledge must be rejected"),
        Err(err) => err,
    };

    assert!(
        matches!(err, Error::WebSocketUnsupported(_))
            || err.to_string().contains("prior knowledge"),
        "unexpected error for missing prior knowledge: {err:?}"
    );
}

#[tokio::test]
async fn rfc8441_wss_with_h1_alpn_is_rejected_for_h2_only_websocket() {
    let (acceptor, ca_cert) = h1_tls_acceptor();
    let server = MockH2Server::new().await.unwrap();
    let url = format!("{}/chat?room=one", server.url_tls()).replace("https://", "wss://");

    server.start_tls(acceptor, |_conn| async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let err = match client.websocket_h2(&url).open().await {
        Ok(_) => panic!("H2-only WebSocket API must reject ALPN http/1.1"),
        Err(err) => err,
    };

    assert!(
        matches!(err, Error::WebSocketUnsupported(_)) || err.to_string().contains("ALPN"),
        "unexpected error for H1 ALPN: {err:?}"
    );
}
