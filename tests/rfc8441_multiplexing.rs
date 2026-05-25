//! RFC 8441 multiplexing tests.
//!
//! These tests intentionally target the public API that the RFC 8441 lane is
//! expected to add. They should fail to compile until that API exists.

use bytes::Bytes;
use specter::Client;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::{watch, Mutex};
use tokio::time::timeout;

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};
use helpers::tls::generate_cert_bundle;

async fn serve_rfc8441_tunnel_and_normal_request(
    conn: MockH2Connection,
    observed: Arc<Mutex<Vec<(u32, &'static str)>>>,
    expected_authority: String,
) {
    conn.read_preface().await.unwrap();

    let (_, frame_type, flags, _, _) = conn.read_frame().await.unwrap();
    assert_eq!(frame_type, 0x04, "client must send SETTINGS first");
    assert_eq!(flags & 0x01, 0, "first client SETTINGS must not be ACK");

    conn.send_settings(&[(0x08, 1), (0x03, 100)]).await.unwrap();
    conn.send_settings_ack().await.unwrap();

    let mut tunnel_stream_id = None;
    let mut normal_stream_id = None;

    while tunnel_stream_id.is_none() || normal_stream_id.is_none() {
        let headers = timeout(Duration::from_secs(5), conn.read_decoded_headers())
            .await
            .expect("timed out waiting for request HEADERS")
            .unwrap();

        if headers.header(":method") == Some("CONNECT") {
            headers.assert_rfc8441_websocket_connect(&expected_authority, "https", "/socket");
            assert_eq!(
                headers.flags & 0x01,
                0,
                "CONNECT HEADERS must keep stream open"
            );
            tunnel_stream_id = Some(headers.stream_id);
            observed.lock().await.push((headers.stream_id, "tunnel"));
            conn.send_headers(headers.stream_id, &[0x88], false, true)
                .await
                .unwrap();
        } else {
            assert_eq!(headers.header(":method"), Some("GET"));
            assert_eq!(headers.header(":path"), Some("/normal"));
            normal_stream_id = Some(headers.stream_id);
            observed.lock().await.push((headers.stream_id, "request"));
            conn.send_headers(headers.stream_id, &[0x88], false, true)
                .await
                .unwrap();
            conn.send_data(headers.stream_id, b"ok", true)
                .await
                .unwrap();
        }
    }

    let tunnel_stream_id = tunnel_stream_id.unwrap();
    let normal_stream_id = normal_stream_id.unwrap();
    assert_ne!(
        tunnel_stream_id, normal_stream_id,
        "RFC 8441 tunnel and normal request must use different streams"
    );
    assert_eq!(tunnel_stream_id % 2, 1);
    assert_eq!(normal_stream_id % 2, 1);
}

async fn serve_direct_stream_or_rfc8441_tunnel(
    conn: MockH2Connection,
    observed: Arc<Mutex<Vec<(usize, u32, &'static str)>>>,
    connection_index: Arc<AtomicUsize>,
    expected_authority: String,
    direct_path: &'static str,
    mut finish_direct_rx: watch::Receiver<bool>,
    keep_direct_open: bool,
) {
    let conn_id = connection_index.fetch_add(1, Ordering::SeqCst) + 1;
    conn.read_preface().await.unwrap();

    let (_, frame_type, flags, _, _) = conn.read_frame().await.unwrap();
    assert_eq!(frame_type, 0x04, "client must send SETTINGS first");
    assert_eq!(flags & 0x01, 0, "first client SETTINGS must not be ACK");

    conn.send_settings(&[(0x08, 1), (0x03, 100)]).await.unwrap();
    conn.send_settings_ack().await.unwrap();

    let headers = timeout(Duration::from_secs(5), conn.read_decoded_headers())
        .await
        .expect("timed out waiting for request HEADERS")
        .unwrap();

    if headers.header(":method") == Some("CONNECT") {
        headers.assert_rfc8441_websocket_connect(&expected_authority, "https", "/socket");
        observed
            .lock()
            .await
            .push((conn_id, headers.stream_id, "tunnel"));
        conn.send_headers(headers.stream_id, &[0x88], false, true)
            .await
            .unwrap();
        let _ = timeout(Duration::from_secs(1), finish_direct_rx.changed()).await;
        return;
    }

    assert_eq!(headers.header(":method"), Some("GET"));
    assert_eq!(headers.header(":path"), Some(direct_path));
    observed
        .lock()
        .await
        .push((conn_id, headers.stream_id, "direct"));
    conn.send_headers(headers.stream_id, &[0x88], false, true)
        .await
        .unwrap();

    if keep_direct_open {
        conn.send_data(headers.stream_id, b"direct-open", false)
            .await
            .unwrap();
        while !*finish_direct_rx.borrow() {
            if timeout(Duration::from_secs(5), finish_direct_rx.changed())
                .await
                .is_err()
            {
                break;
            }
        }
        conn.send_data(headers.stream_id, b"direct-close", true)
            .await
            .unwrap();
    } else {
        conn.send_data(headers.stream_id, b"direct-done", true)
            .await
            .unwrap();
        if let Ok(Ok(extra_headers)) =
            timeout(Duration::from_millis(250), conn.read_decoded_headers()).await
        {
            observed.lock().await.push((
                conn_id,
                extra_headers.stream_id,
                "unexpected-direct-reuse",
            ));
        }
    }
}

#[tokio::test]
async fn rfc8441_tunnel_and_normal_h2_request_share_one_connection() {
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let base_url = server.url_tls();
    let authority = format!("127.0.0.1:{}", server.port());
    let observed = Arc::new(Mutex::new(Vec::new()));
    let observed_for_server = observed.clone();

    server.start_tls(acceptor, move |conn| {
        serve_rfc8441_tunnel_and_normal_request(
            conn,
            observed_for_server.clone(),
            authority.clone(),
        )
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .h2_direct_streaming_responses(true)
        .build()
        .unwrap();

    let tunnel_url = format!("{base_url}/socket").replace("https://", "wss://");
    let normal_url = format!("{base_url}/normal");

    let tunnel = timeout(
        Duration::from_secs(5),
        client.websocket_h2(&tunnel_url).open(),
    )
    .await
    .expect("RFC 8441 tunnel open timed out")
    .expect("RFC 8441 tunnel should open over ALPN h2");

    let response = timeout(
        Duration::from_secs(5),
        client.get(normal_url.as_str()).send(),
    )
    .await
    .expect("normal request timed out")
    .expect("normal H2 request should complete while tunnel is open");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.buffered_bytes().unwrap_or(&Bytes::new()).as_ref(),
        b"ok"
    );
    drop(tunnel);

    let observed = observed.lock().await;
    assert_eq!(observed.len(), 2, "server should see both streams");
    assert!(observed.iter().any(|(_, kind)| *kind == "tunnel"));
    assert!(observed.iter().any(|(_, kind)| *kind == "request"));
}

#[tokio::test]
async fn rfc8441_opens_while_h2_direct_body_is_active() {
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let base_url = server.url_tls();
    let authority = format!("127.0.0.1:{}", server.port());
    let observed = Arc::new(Mutex::new(Vec::new()));
    let connection_index = Arc::new(AtomicUsize::new(0));
    let (finish_direct_tx, finish_direct_rx) = watch::channel(false);
    let observed_for_server = observed.clone();
    let connection_index_for_server = connection_index.clone();

    server.start_tls(acceptor, move |conn| {
        serve_direct_stream_or_rfc8441_tunnel(
            conn,
            observed_for_server.clone(),
            connection_index_for_server.clone(),
            authority.clone(),
            "/stream",
            finish_direct_rx.clone(),
            true,
        )
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .h2_direct_streaming_responses(true)
        .build()
        .unwrap();

    let stream_url = format!("{base_url}/stream");
    let tunnel_url = format!("{base_url}/socket").replace("https://", "wss://");

    let mut response = timeout(
        Duration::from_secs(5),
        client.get(stream_url.as_str()).send_streaming(),
    )
    .await
    .expect("direct H2 streaming response timed out")
    .expect("direct H2 streaming response should open");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from_static(b"direct-open")
    );

    let tunnel = timeout(
        Duration::from_secs(5),
        client.websocket_h2(&tunnel_url).open(),
    )
    .await
    .expect("RFC 8441 tunnel open timed out while direct body is active")
    .expect("RFC 8441 tunnel should open while direct H2 body is active");

    let observed = observed.lock().await;
    let direct = observed
        .iter()
        .find(|(_, _, kind)| *kind == "direct")
        .expect("server should observe direct streaming request");
    let tunnel_observed = observed
        .iter()
        .find(|(_, _, kind)| *kind == "tunnel")
        .expect("server should observe RFC 8441 tunnel");
    assert_ne!(
        direct.0, tunnel_observed.0,
        "active H2 direct body and RFC 8441 tunnel must not share the direct-owned connection"
    );
    drop(observed);

    finish_direct_tx.send(true).unwrap();
    drop(tunnel);
    drop(response);
}

#[tokio::test]
async fn rfc8441_does_not_reuse_idle_h2_direct_pool_connection() {
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let server = MockH2Server::new().await.unwrap();
    let base_url = server.url_tls();
    let authority = format!("127.0.0.1:{}", server.port());
    let observed = Arc::new(Mutex::new(Vec::new()));
    let connection_index = Arc::new(AtomicUsize::new(0));
    let (_finish_direct_tx, finish_direct_rx) = watch::channel(false);
    let observed_for_server = observed.clone();
    let connection_index_for_server = connection_index.clone();

    server.start_tls(acceptor, move |conn| {
        serve_direct_stream_or_rfc8441_tunnel(
            conn,
            observed_for_server.clone(),
            connection_index_for_server.clone(),
            authority.clone(),
            "/stream",
            finish_direct_rx.clone(),
            false,
        )
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .h2_direct_streaming_responses(true)
        .build()
        .unwrap();

    let stream_url = format!("{base_url}/stream");
    let tunnel_url = format!("{base_url}/socket").replace("https://", "wss://");

    let mut response = timeout(
        Duration::from_secs(5),
        client.get(stream_url.as_str()).send_streaming(),
    )
    .await
    .expect("direct H2 streaming response timed out")
    .expect("direct H2 streaming response should open");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from_static(b"direct-done")
    );
    assert!(response.body_mut().frame().await.is_none());

    let tunnel = timeout(
        Duration::from_secs(5),
        client.websocket_h2(&tunnel_url).open(),
    )
    .await
    .expect("RFC 8441 tunnel open timed out after direct body drained")
    .expect("RFC 8441 tunnel should not depend on the direct H2 pool");
    drop(tunnel);

    let observed = observed.lock().await;
    assert!(
        !observed
            .iter()
            .any(|(_, _, kind)| *kind == "unexpected-direct-reuse"),
        "RFC 8441 CONNECT must not be sent on an idle direct-body connection: {observed:?}"
    );
    let direct = observed
        .iter()
        .find(|(_, _, kind)| *kind == "direct")
        .expect("server should observe direct streaming request");
    let tunnel = observed
        .iter()
        .find(|(_, _, kind)| *kind == "tunnel")
        .expect("server should observe RFC 8441 tunnel");
    assert_ne!(
        direct.0, tunnel.0,
        "idle H2 direct pool connection must not be reused for RFC 8441 tunnels"
    );
}
