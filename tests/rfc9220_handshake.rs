use specter::{Client, Error};
use std::time::Duration;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h3_server::{MockEvent, MockH3Connection, MockH3Server};

async fn read_connect_stream(conn: &MockH3Connection) -> u64 {
    loop {
        match timeout(Duration::from_secs(5), conn.read_event())
            .await
            .expect("timed out waiting for RFC 9220 CONNECT")
            .expect("mock connection closed before CONNECT")
        {
            MockEvent::Headers { stream_id, headers } => {
                assert_eq!(headers[0], (":method".into(), "CONNECT".into()));
                assert_eq!(headers[1], (":protocol".into(), "websocket".into()));
                return stream_id;
            }
            _ => continue,
        }
    }
}

#[tokio::test]
async fn rfc9220_successful_open_requires_status_200() {
    let server = MockH3Server::new_with_extended_connect().await.unwrap();
    let url = server.url().replace("https://", "wss://") + "/chat";

    server.start(|conn| async move {
        let stream_id = read_connect_stream(&conn).await;
        conn.send_response_headers(stream_id, vec![(":status", "200")], false)
            .await;
    });

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    timeout(Duration::from_secs(5), client.websocket_h3(&url).open())
        .await
        .expect("RFC 9220 open timed out")
        .expect("status 200 must open the tunnel");
}

#[tokio::test]
async fn rfc9220_rejects_status_101() {
    let server = MockH3Server::new_with_extended_connect().await.unwrap();
    let url = server.url().replace("https://", "wss://") + "/chat";

    server.start(|conn| async move {
        let stream_id = read_connect_stream(&conn).await;
        conn.send_response_headers(stream_id, vec![(":status", "101")], true)
            .await;
    });

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let err = timeout(Duration::from_secs(5), client.websocket_h3(&url).open())
        .await
        .expect("RFC 9220 101 rejection timed out")
        .expect_err("HTTP/3 WebSocket must not accept 101");

    assert!(
        matches!(
            err,
            Error::HttpProtocol(_) | Error::WebSocketHandshake { .. }
        ),
        "unexpected 101 error: {err:?}"
    );
}

#[tokio::test]
async fn rfc9220_rejects_non_200_status() {
    let server = MockH3Server::new_with_extended_connect().await.unwrap();
    let url = server.url().replace("https://", "wss://") + "/chat";

    server.start(|conn| async move {
        let stream_id = read_connect_stream(&conn).await;
        conn.send_response_headers(stream_id, vec![(":status", "404")], true)
            .await;
    });

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let err = timeout(Duration::from_secs(5), client.websocket_h3(&url).open())
        .await
        .expect("RFC 9220 non-200 rejection timed out")
        .expect_err("HTTP/3 WebSocket must reject non-200 status");

    assert!(
        matches!(err, Error::WebSocketHandshake { status: 404, .. }),
        "unexpected non-200 error: {err:?}"
    );
}
