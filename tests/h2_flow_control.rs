//! HTTP/2 Flow Control Tests
//!
//! Verifies that the client correctly respects flow control windows
//! and waits for WINDOW_UPDATE frames during large uploads.

use specter::Client;
use std::time::Duration;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};

async fn perform_handshake(conn: &MockH2Connection) -> std::io::Result<()> {
    conn.read_preface().await?;
    let (_, frame_type, _, _, _) = conn.read_frame().await?;
    assert_eq!(frame_type, 0x04);

    // Set small window size (e.g. 100 bytes)
    conn.send_settings(&[
        (0x03, 100), // MAX_CONCURRENT_STREAMS
        (0x04, 65535), // INITIAL_WINDOW_SIZE (Stream) - keep large?
                     // Actually, client respects Peer Settings.
                     // Setting 0x04 controls stream-level window.
    ])
    .await?;

    // But we also have Connection-level window (default 65535).
    // To test flow control, we can consume window by reading DATA.
    // Or we can set INITIAL_WINDOW_SIZE to small value via SETTINGS.

    conn.send_settings_ack().await?;
    let (_, frame_type, flags, _, _) = conn.read_frame().await?;
    assert_eq!(frame_type, 0x04);
    assert_eq!(flags & 0x01, 0x01);

    Ok(())
}

#[tokio::test]
async fn test_large_upload_flow_control() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("trace")
        .try_init();

    let server = MockH2Server::new().await.unwrap();
    let url = format!("http://127.0.0.1:{}/upload", server.port());

    // Body larger than default window (65535)
    // We'll use 70000 bytes.
    let body_size = 70000;
    let initial_window_size = 65535;

    let mut body = Vec::with_capacity(body_size);
    for i in 0..body_size {
        body.push((i % 255) as u8);
    }
    let body_clone = body.clone();

    let _handle = server.start(move |conn| async move {
        tracing::info!("Server: reading preface");
        conn.read_preface().await.unwrap();

        // We don't send custom settings, just use defaults.
        // We do expect the client to send its settings.

        let mut total_received = 0;
        let mut stream_id = 0;
        let mut window_update_sent = false;

        loop {
            let (len, frame_type, flags, sid, payload) = conn.read_frame().await.unwrap();
            tracing::info!(
                "Server: received Type={} Flags={} Len={} ID={}",
                frame_type,
                flags,
                len,
                sid
            );

            if frame_type == 0x01 {
                // HEADERS
                stream_id = sid;
                tracing::info!("Server: Stream ID {} established", stream_id);
            } else if frame_type == 0x00 {
                // DATA
                total_received += len as usize;
                tracing::info!("Server: Total received: {}", total_received);

                if total_received >= initial_window_size && !window_update_sent {
                    tracing::info!("Server: Window exhausted. Checking for block.");

                    // We expect silence now (client blocked)
                    // Wait a bit to verify no more data comes
                    let result = timeout(Duration::from_millis(100), conn.read_frame()).await;
                    if result.is_ok() {
                        // If we got a frame, it SHOULD NOT be Data.
                        // It could be something else (like Priority).
                        // But for this test, we assume silence or non-data.
                        // If we got DATA, then flow control is broken.
                        let (_, t, _, _, _) = result.unwrap().unwrap();
                        assert_ne!(t, 0x00, "Received DATA when window exhausted!");
                    }

                    tracing::info!("Server: Sending Window Update");
                    // Update both Stream and Connection windows
                    // Wait, Specter checks BOTH.
                    // Example: We consumed 65535.
                    // We need to give credit back.

                    // Helper: Just give enough for the rest
                    let remaining = body_size - total_received;
                    conn.send_window_update(0, remaining as u32).await.unwrap(); // Connection level
                    conn.send_window_update(stream_id, remaining as u32)
                        .await
                        .unwrap(); // Stream level

                    window_update_sent = true;
                }
            } else if frame_type == 0x04 && (flags & 0x01) == 0 {
                // Settings (not ack) - Client sent settings
                tracing::info!("Server: Received Settings, sending ACK");
                conn.send_settings_ack().await.unwrap();
                // Also send our settings? Nah, defaults are fine.
            }

            if total_received >= body_size {
                break;
            }
        }

        assert_eq!(total_received, body_size);
        tracing::info!("Server: All data received. Sending response.");
        conn.send_headers(stream_id, &[0x88], true, true)
            .await
            .unwrap(); // 200 OK
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = Client::builder()
        .prefer_http2(true)
        .http2_prior_knowledge(true)
        .build()
        .unwrap();
    let res = client.post(&url).body(body_clone).send().await.unwrap();

    assert!(res.is_success());
}
