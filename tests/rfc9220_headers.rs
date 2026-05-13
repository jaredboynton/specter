use specter::{Client, Error};
use std::time::Duration;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h3_server::{MockEvent, MockH3Connection, MockH3Server};

async fn read_headers(conn: &MockH3Connection) -> (u64, Vec<(String, String)>) {
    loop {
        match timeout(Duration::from_secs(5), conn.read_event())
            .await
            .expect("timed out waiting for H3 request headers")
            .expect("mock connection closed before headers")
        {
            MockEvent::Headers { stream_id, headers } => return (stream_id, headers),
            _ => continue,
        }
    }
}

#[tokio::test]
async fn rfc9220_extended_connect_sends_required_pseudo_headers_in_order() {
    let server = MockH3Server::new_with_extended_connect().await.unwrap();
    let url = server.url().replace("https://", "wss://") + "/chat?room=one";
    let authority = format!("127.0.0.1:{}", server.port());

    server.start(move |conn| {
        let authority = authority.clone();
        async move {
            let (stream_id, headers) = read_headers(&conn).await;
            assert_eq!(
                &headers[..5],
                &[
                    (":method".into(), "CONNECT".into()),
                    (":protocol".into(), "websocket".into()),
                    (":scheme".into(), "https".into()),
                    (":path".into(), "/chat?room=one".into()),
                    (":authority".into(), authority),
                ]
            );
            assert!(headers.contains(&("origin".into(), "https://app.example".into())));
            assert!(headers.contains(&("sec-websocket-protocol".into(), "chat".into())));
            conn.send_response_headers(stream_id, vec![(":status", "200")], false)
                .await;
        }
    });

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    timeout(
        Duration::from_secs(5),
        client
            .websocket_h3(&url)
            .header("Origin", "https://app.example")
            .header("Sec-WebSocket-Protocol", "chat")
            .open(),
    )
    .await
    .expect("RFC 9220 open timed out")
    .expect("valid RFC 9220 tunnel should open");
}

#[tokio::test]
async fn rfc9220_rejects_h1_websocket_bootstrap_headers() {
    let server = MockH3Server::new_with_extended_connect().await.unwrap();
    let url = server.url().replace("https://", "wss://") + "/chat";

    server.start(|conn| async move {
        let event = timeout(Duration::from_millis(300), conn.read_event()).await;
        assert!(
            event.is_err(),
            "forbidden RFC 9220 headers must fail before CONNECT headers are sent"
        );
    });

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    for name in [
        "Connection",
        "Upgrade",
        "Host",
        "Sec-WebSocket-Key",
        "Sec-WebSocket-Accept",
        "Sec-WebSocket-Extensions",
    ] {
        let err = client
            .websocket_h3(&url)
            .header(name, "bad")
            .open()
            .await
            .expect_err("forbidden header must be rejected");
        assert!(
            matches!(err, Error::WebSocketUnsupported(_) | Error::HttpProtocol(_)),
            "unexpected error for {name}: {err:?}"
        );
        assert!(err.to_string().contains("not allowed"));
    }
}
