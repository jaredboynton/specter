use bytes::Bytes;
use http::Uri;
use specter::fingerprint::http2::Http2Settings;
use specter::transport::h2::{
    flags, FrameHeader, FrameType, H2TunnelOutbound, PseudoHeaderOrder, RawH2Connection,
    SettingsFrame, CONNECTION_PREFACE, FRAME_HEADER_SIZE,
};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

async fn read_client_preface_and_settings(server: &mut DuplexStream) {
    let mut preface = vec![0; CONNECTION_PREFACE.len()];
    server.read_exact(&mut preface).await.unwrap();
    assert_eq!(preface, CONNECTION_PREFACE);

    let _ = read_frame(server).await;
    let _ = read_frame(server).await;
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

async fn write_headers(
    server: &mut DuplexStream,
    stream_id: u32,
    header_block: &[u8],
    end_stream: bool,
) {
    let headers =
        specter::transport::h2::HeadersFrame::new(stream_id, Bytes::copy_from_slice(header_block))
            .end_headers(true)
            .end_stream(end_stream);
    server.write_all(&headers.serialize()).await.unwrap();
}

#[tokio::test]
async fn rfc8441_tunnel_send_bytes_preserves_end_stream_for_driver_flush() {
    let (outbound_tx, mut outbound_rx) = mpsc::channel(4);
    let (_inbound_tx, inbound_rx) = mpsc::channel(4);
    let tunnel = specter::transport::h2::H2Tunnel::new(outbound_tx, inbound_rx);

    tunnel
        .send_bytes(Bytes::from_static(b"final"), true)
        .await
        .expect("send queued");

    let H2TunnelOutbound { bytes, end_stream } = outbound_rx.recv().await.unwrap();
    assert_eq!(bytes, Bytes::from_static(b"final"));
    assert!(end_stream);
}

#[tokio::test]
async fn rfc8441_tunnel_close_send_queues_empty_end_stream() {
    let (outbound_tx, mut outbound_rx) = mpsc::channel(4);
    let (_inbound_tx, inbound_rx) = mpsc::channel(4);
    let tunnel = specter::transport::h2::H2Tunnel::new(outbound_tx, inbound_rx);

    tunnel.close_send().await.expect("close queued");

    let H2TunnelOutbound { bytes, end_stream } = outbound_rx.recv().await.unwrap();
    assert!(bytes.is_empty());
    assert!(end_stream);
}

#[tokio::test]
async fn rfc8441_zero_length_end_stream_data_is_sent_with_exhausted_stream_window() {
    let (client, mut server) = duplex(8192);
    let client_task = tokio::spawn(async move {
        let mut conn =
            RawH2Connection::connect(client, Http2Settings::default(), PseudoHeaderOrder::Chrome)
                .await
                .unwrap();
        let uri: Uri = "https://example.com/chat".parse().unwrap();
        let stream_id = conn
            .open_extended_connect_websocket(&uri, vec![])
            .await
            .unwrap();
        conn.send_data(stream_id, &[], true).await.unwrap()
    });

    read_client_preface_and_settings(&mut server).await;
    write_settings(&mut server, &[(0x8, 1), (0x4, 0)]).await;

    let (connect, _) = read_headers_frame(&mut server).await;
    assert_eq!(connect.stream_id, 1);
    write_headers(&mut server, connect.stream_id, &[0x88], false).await;

    let (data, payload) = timeout(Duration::from_secs(1), async {
        loop {
            let (header, payload) = read_non_ack_frame(&mut server).await;
            if header.frame_type == FrameType::Data {
                break (header, payload);
            }
        }
    })
    .await
    .expect("zero-length END_STREAM DATA must not wait for send window");

    assert_eq!(data.stream_id, connect.stream_id);
    assert_eq!(data.length, 0);
    assert_eq!(payload.len(), 0);
    assert_eq!(data.flags & flags::END_STREAM, flags::END_STREAM);
    assert_eq!(client_task.await.unwrap(), 0);
}
