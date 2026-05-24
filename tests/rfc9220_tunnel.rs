use bytes::Bytes;
use specter::{Client, H3Backend, H3TunnelEvent};
use std::time::Duration;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h3_server::{MockEvent, MockH3Connection, MockH3Server};

async fn accept_tunnel(conn: &MockH3Connection) -> u64 {
    loop {
        match timeout(Duration::from_secs(5), conn.read_event())
            .await
            .expect("timed out waiting for RFC 9220 CONNECT")
            .expect("mock connection closed before CONNECT")
        {
            MockEvent::Headers { stream_id, headers } => {
                assert_eq!(headers[0], (":method".into(), "CONNECT".into()));
                assert_eq!(headers[1], (":protocol".into(), "websocket".into()));
                conn.send_response_headers(stream_id, vec![(":status", "200")], false)
                    .await;
                return stream_id;
            }
            _ => continue,
        }
    }
}

#[tokio::test]
async fn rfc9220_tunnel_carries_websocket_frame_bytes_in_h3_data() {
    let server = MockH3Server::new_with_extended_connect().await.unwrap();
    let url = server.url().replace("https://", "wss://") + "/chat";

    server.start(|conn| async move {
        let stream_id = accept_tunnel(&conn).await;

        loop {
            match timeout(Duration::from_secs(5), conn.read_event())
                .await
                .expect("timed out waiting for client DATA")
                .expect("mock connection closed before DATA")
            {
                MockEvent::Data {
                    stream_id: sid,
                    data,
                    ..
                } if sid == stream_id => {
                    assert_eq!(data, b"\x81\x02hi");
                    conn.send_response_data(stream_id, b"\x81\x02ok", false)
                        .await;
                    return;
                }
                _ => continue,
            }
        }
    });

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let mut tunnel = timeout(Duration::from_secs(5), client.websocket_h3(&url).open())
        .await
        .expect("RFC 9220 open timed out")
        .expect("tunnel should open");

    tunnel
        .send_bytes(Bytes::from_static(b"\x81\x02hi"), false)
        .await
        .unwrap();

    let inbound = timeout(Duration::from_secs(5), tunnel.recv_bytes())
        .await
        .expect("timed out waiting for tunnel DATA")
        .expect("tunnel event stream ended")
        .expect("tunnel recv failed");
    assert_eq!(inbound, Bytes::from_static(b"\x81\x02ok"));
}

#[tokio::test]
async fn native_h3_rfc9220_tunnel_carries_websocket_frame_bytes_in_h3_data() {
    let server = MockH3Server::new_with_extended_connect().await.unwrap();
    let url = server.url().replace("https://", "wss://") + "/chat";

    server.start(|conn| async move {
        let stream_id = accept_tunnel(&conn).await;

        loop {
            match timeout(Duration::from_secs(5), conn.read_event())
                .await
                .expect("timed out waiting for native client DATA")
                .expect("mock connection closed before native DATA")
            {
                MockEvent::Data {
                    stream_id: sid,
                    data,
                    ..
                } if sid == stream_id => {
                    assert_eq!(data, b"\x81\x02hi");
                    conn.send_response_data(stream_id, b"\x81\x02ok", false)
                        .await;
                    return;
                }
                _ => continue,
            }
        }
    });

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .h3_backend(H3Backend::Native)
        .build()
        .unwrap();

    let mut tunnel = timeout(Duration::from_secs(5), client.websocket_h3(&url).open())
        .await
        .expect("native RFC 9220 open timed out")
        .expect("native tunnel should open");

    tunnel
        .send_bytes(Bytes::from_static(b"\x81\x02hi"), false)
        .await
        .unwrap();

    let inbound = timeout(Duration::from_secs(5), tunnel.recv_bytes())
        .await
        .expect("timed out waiting for native tunnel DATA")
        .expect("native tunnel event stream ended")
        .expect("native tunnel recv failed");
    assert_eq!(inbound, Bytes::from_static(b"\x81\x02ok"));
}

#[tokio::test]
async fn rfc9220_remote_fin_maps_to_end_stream() {
    let server = MockH3Server::new_with_extended_connect().await.unwrap();
    let url = server.url().replace("https://", "wss://") + "/chat";

    server.start(|conn| async move {
        let stream_id = accept_tunnel(&conn).await;
        conn.finish_stream(stream_id).await;
    });

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let mut tunnel = timeout(Duration::from_secs(5), client.websocket_h3(&url).open())
        .await
        .expect("RFC 9220 open timed out")
        .expect("tunnel should open");

    let event = timeout(Duration::from_secs(5), tunnel.recv_event())
        .await
        .expect("timed out waiting for end stream")
        .expect("event stream ended")
        .expect("event failed");

    assert_eq!(event, H3TunnelEvent::EndStream);
}
