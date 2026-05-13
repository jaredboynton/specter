use specter::{Client, Error};
use std::time::Duration;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h3_server::MockH3Server;

#[tokio::test]
async fn rfc9220_does_not_send_extended_connect_before_server_enables_it() {
    let server = MockH3Server::new().await.unwrap();
    let url = server.url().replace("https://", "wss://") + "/chat";

    server.start(|conn| async move {
        let event = timeout(Duration::from_millis(300), conn.read_event()).await;
        assert!(
            event.is_err(),
            "client must not send RFC 9220 CONNECT when server omits SETTINGS_ENABLE_CONNECT_PROTOCOL"
        );
    });

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let err = timeout(Duration::from_secs(5), client.websocket_h3(&url).open())
        .await
        .expect("RFC 9220 settings gate timed out")
        .expect_err("server without SETTINGS_ENABLE_CONNECT_PROTOCOL must be rejected");

    assert!(
        matches!(err, Error::WebSocketUnsupported(_)),
        "expected unsupported error for missing RFC 9220 setting, got {err:?}"
    );
    assert!(err.to_string().contains("SETTINGS_ENABLE_CONNECT_PROTOCOL"));
}

#[tokio::test]
async fn rfc9220_ws_scheme_is_rejected_before_quic() {
    let server = MockH3Server::new_with_extended_connect().await.unwrap();
    let url = server.url().replace("https://", "ws://") + "/chat";

    server.start(|conn| async move {
        let event = timeout(Duration::from_millis(300), conn.read_event()).await;
        assert!(
            event.is_err(),
            "ws:// must fail before any HTTP/3 request stream is sent"
        );
    });

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let err = client
        .websocket_h3(&url)
        .open()
        .await
        .expect_err("RFC 9220 requires wss://");

    assert!(
        matches!(err, Error::WebSocketUnsupported(_)),
        "unexpected ws:// rejection error: {err:?}"
    );
}
