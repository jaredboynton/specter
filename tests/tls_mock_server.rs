use specter::Client;
use std::time::Duration;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};
use helpers::mock_server::MockHttpServer;
use helpers::tls::generate_cert_bundle;

#[tokio::test]
async fn test_h1_tls() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("trace")
        .try_init();

    // Generate certs
    let (mut builder, ca_cert) = generate_cert_bundle();
    // ALPN for HTTP/1.1
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x08http/1.1", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    // Start Server
    let server = MockHttpServer::new().await.unwrap();
    let url = server.url_tls();
    server.start_tls(acceptor);

    // Create Client with CA
    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .build()
        .unwrap();

    // Send request
    let resp = client.get(&url).send().await.unwrap();

    assert_eq!(resp.status, 200);
    assert_eq!(resp.http_version(), "HTTP/1.1");
    let body = resp.text().unwrap();
    assert!(body.contains("Hello"));
}

#[tokio::test]
async fn test_h2_tls() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("trace")
        .try_init();

    // Generate certs
    let (mut builder, ca_cert) = generate_cert_bundle();
    // ALPN for H2
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();

    // Start Server
    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    server.start_tls(acceptor, |conn: MockH2Connection| async move {
        // Read Preface
        if let Err(e) = conn.read_preface().await {
            tracing::error!("Preface error: {}", e);
            return;
        }

        // Handshake
        let stream_id = loop {
            let (_, frame_type, flags, sid, _) = conn.read_frame().await.unwrap();
            match frame_type {
                0x01 => {
                    // HEADERS
                    break sid;
                }
                0x04 => {
                    // SETTINGS
                    if flags & 0x01 == 0 {
                        conn.send_settings(&[(0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                    }
                }
                _ => {}
            }
        };

        // Send Response
        // Encode "content-length: 5", "hello"
        // Minimal headers: :status 200
        let headers = vec![
            0x88, // :status 200
        ];

        conn.send_headers(stream_id, &headers, false, true)
            .await
            .unwrap();
        conn.send_data(stream_id, b"Hello", true).await.unwrap();
    });

    // Create Client with CA
    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    // Send request (ensure we use https)
    let result = timeout(Duration::from_secs(2), client.get(&url).send()).await;

    assert!(result.is_ok(), "Request timed out");
    let resp = result.unwrap().unwrap();

    assert_eq!(resp.status, 200);
    assert_eq!(resp.http_version(), "HTTP/2");
    assert_eq!(resp.text().unwrap(), "Hello");
}
