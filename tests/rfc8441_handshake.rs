use bytes::Bytes;
use http::Uri;
use specter::fingerprint::http2::Http2Settings;
use specter::transport::h2::{
    flags, FrameHeader, FrameType, HpackDecoder, PseudoHeaderOrder, RawH2Connection, SettingsFrame,
    CONNECTION_PREFACE, FRAME_HEADER_SIZE,
};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::{timeout, Duration};

async fn read_client_preface_and_settings(server: &mut DuplexStream) {
    let mut preface = vec![0; CONNECTION_PREFACE.len()];
    server.read_exact(&mut preface).await.unwrap();
    assert_eq!(preface, CONNECTION_PREFACE);

    let (_header, _payload) = read_frame(server).await;
    let (_header, _payload) = read_frame(server).await;
}

async fn read_frame(server: &mut DuplexStream) -> (FrameHeader, Bytes) {
    let mut header_bytes = [0u8; FRAME_HEADER_SIZE];
    server.read_exact(&mut header_bytes).await.unwrap();
    let header = FrameHeader::parse(&header_bytes).unwrap();
    let mut payload = vec![0; header.length as usize];
    if header.length > 0 {
        server.read_exact(&mut payload).await.unwrap();
    }
    (header, Bytes::from(payload))
}

async fn read_non_ack_frame(server: &mut DuplexStream) -> (FrameHeader, Bytes) {
    loop {
        let (header, payload) = read_frame(server).await;
        if header.frame_type == FrameType::Settings && (header.flags & flags::ACK) != 0 {
            continue;
        }
        return (header, payload);
    }
}

async fn read_headers_frame(server: &mut DuplexStream) -> (FrameHeader, Bytes) {
    loop {
        let (header, payload) = read_non_ack_frame(server).await;
        if header.frame_type == FrameType::Headers {
            return (header, payload);
        }
    }
}

async fn maybe_read_headers_frame(server: &mut DuplexStream) -> Option<(FrameHeader, Bytes)> {
    loop {
        let mut header_bytes = [0u8; FRAME_HEADER_SIZE];
        if server.read_exact(&mut header_bytes).await.is_err() {
            return None;
        }
        let header = FrameHeader::parse(&header_bytes).unwrap();
        let mut payload = vec![0; header.length as usize];
        if header.length > 0 && server.read_exact(&mut payload).await.is_err() {
            return None;
        }
        if header.frame_type == FrameType::Settings && (header.flags & flags::ACK) != 0 {
            continue;
        }
        if header.frame_type == FrameType::Headers {
            return Some((header, Bytes::from(payload)));
        }
    }
}

async fn write_settings(server: &mut DuplexStream, settings: &[(u16, u32)]) {
    server
        .write_all(
            &SettingsFrame {
                settings: settings.to_vec(),
                ack: false,
            }
            .serialize(),
        )
        .await
        .unwrap();
}

async fn write_headers(server: &mut DuplexStream, stream_id: u32, header_block: &[u8]) {
    let header =
        specter::transport::h2::HeadersFrame::new(stream_id, Bytes::copy_from_slice(header_block))
            .end_headers(true)
            .end_stream(false);
    server.write_all(&header.serialize()).await.unwrap();
}

fn hpack_status(status: &str) -> Vec<u8> {
    match status {
        "200" => vec![0x88],
        other => {
            let mut encoded = vec![0x08, other.len() as u8];
            encoded.extend_from_slice(other.as_bytes());
            encoded
        }
    }
}

#[tokio::test]
async fn rfc8441_refuses_before_settings_enable_without_sending_headers() {
    let (client, mut server) = duplex(8192);
    let client_task = tokio::spawn(async move {
        let mut conn =
            RawH2Connection::connect(client, Http2Settings::default(), PseudoHeaderOrder::Chrome)
                .await
                .unwrap();
        let uri: Uri = "https://example.com/chat".parse().unwrap();
        conn.open_extended_connect_websocket(&uri, vec![]).await
    });

    read_client_preface_and_settings(&mut server).await;
    write_settings(&mut server, &[]).await;

    let err = client_task.await.unwrap().unwrap_err().to_string();
    assert!(err.contains("SETTINGS_ENABLE_CONNECT_PROTOCOL"));
    assert!(
        timeout(
            Duration::from_millis(100),
            maybe_read_headers_frame(&mut server)
        )
        .await
        .map(|frame| frame.is_none())
        .unwrap_or(true),
        "client must not send CONNECT HEADERS before RFC 8441 is enabled"
    );
}

#[tokio::test]
async fn rfc8441_enable_setting_allows_extended_connect_headers() {
    let (client, mut server) = duplex(8192);
    let client_task = tokio::spawn(async move {
        let mut conn =
            RawH2Connection::connect(client, Http2Settings::default(), PseudoHeaderOrder::Chrome)
                .await
                .unwrap();
        let uri: Uri = "https://example.com/chat?room=1".parse().unwrap();
        conn.open_extended_connect_websocket(
            &uri,
            vec![("origin".into(), "https://example.com".into())],
        )
        .await
    });

    read_client_preface_and_settings(&mut server).await;
    write_settings(&mut server, &[(0x8, 1)]).await;

    let (header, payload) = read_headers_frame(&mut server).await;
    assert_eq!(header.frame_type, FrameType::Headers);
    assert_eq!(header.stream_id, 1);
    assert_eq!(header.flags & flags::END_HEADERS, flags::END_HEADERS);
    assert_eq!(header.flags & flags::END_STREAM, 0);

    let mut decoder = HpackDecoder::new();
    let decoded = decoder.decode(&payload).unwrap();
    assert_eq!(
        decoded[..5],
        [
            (":method".into(), "CONNECT".into()),
            (":protocol".into(), "websocket".into()),
            (":scheme".into(), "https".into()),
            (":path".into(), "/chat?room=1".into()),
            (":authority".into(), "example.com".into()),
        ]
    );
    assert!(decoded.contains(&("origin".into(), "https://example.com".into())));

    write_headers(&mut server, header.stream_id, &hpack_status("200")).await;
    assert_eq!(client_task.await.unwrap().unwrap(), 1);
}

#[tokio::test]
async fn rfc8441_101_switching_protocols_fails_without_open_tunnel() {
    let (client, mut server) = duplex(8192);
    let client_task = tokio::spawn(async move {
        let mut conn =
            RawH2Connection::connect(client, Http2Settings::default(), PseudoHeaderOrder::Chrome)
                .await
                .unwrap();
        let uri: Uri = "https://example.com/chat".parse().unwrap();
        conn.open_extended_connect_websocket(&uri, vec![]).await
    });

    read_client_preface_and_settings(&mut server).await;
    write_settings(&mut server, &[(0x8, 1)]).await;
    let (header, _payload) = read_headers_frame(&mut server).await;
    write_headers(&mut server, header.stream_id, &hpack_status("101")).await;

    let err = client_task.await.unwrap().unwrap_err().to_string();
    assert!(err.contains("101"));
    assert!(err.contains("WebSocket"));
}

#[tokio::test]
async fn rfc8441_rejects_extensions_without_shared_codec_before_wire_write() {
    let (client, mut server) = duplex(8192);
    let client_task = tokio::spawn(async move {
        let mut conn =
            RawH2Connection::connect(client, Http2Settings::default(), PseudoHeaderOrder::Chrome)
                .await
                .unwrap();
        let uri: Uri = "https://example.com/chat".parse().unwrap();
        conn.open_extended_connect_websocket(
            &uri,
            vec![(
                "Sec-WebSocket-Extensions".to_string(),
                "permessage-deflate".to_string(),
            )],
        )
        .await
    });

    read_client_preface_and_settings(&mut server).await;
    write_settings(&mut server, &[(0x8, 1)]).await;

    let err = client_task.await.unwrap().unwrap_err().to_string();
    assert!(err.contains("sec-websocket-extensions"));
    assert!(
        timeout(
            Duration::from_millis(100),
            maybe_read_headers_frame(&mut server)
        )
        .await
        .map(|frame| frame.is_none())
        .unwrap_or(true),
        "extensions must be rejected before RFC 8441 CONNECT HEADERS are written"
    );
}

#[tokio::test]
async fn rfc8441_settings_reject_invalid_value_and_downgrade() {
    let (client, mut server) = duplex(8192);
    let invalid_task = tokio::spawn(async move {
        let mut conn =
            RawH2Connection::connect(client, Http2Settings::default(), PseudoHeaderOrder::Chrome)
                .await
                .unwrap();
        let uri: Uri = "https://example.com/chat".parse().unwrap();
        conn.open_extended_connect_websocket(&uri, vec![]).await
    });

    read_client_preface_and_settings(&mut server).await;
    write_settings(&mut server, &[(0x8, 2)]).await;
    let invalid_err = invalid_task.await.unwrap().unwrap_err().to_string();
    assert!(invalid_err.contains("SETTINGS_ENABLE_CONNECT_PROTOCOL"));

    let (client, mut server) = duplex(8192);
    let downgrade_task = tokio::spawn(async move {
        let mut conn =
            RawH2Connection::connect(client, Http2Settings::default(), PseudoHeaderOrder::Chrome)
                .await
                .unwrap();
        let uri: Uri = "https://example.com/chat".parse().unwrap();
        conn.open_extended_connect_websocket(&uri, vec![]).await
    });

    read_client_preface_and_settings(&mut server).await;
    write_settings(&mut server, &[(0x8, 1), (0x8, 0)]).await;
    let downgrade_err = downgrade_task.await.unwrap().unwrap_err().to_string();
    assert!(downgrade_err.contains("downgrade"));
}
