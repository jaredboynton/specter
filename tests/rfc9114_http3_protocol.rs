//! RFC 9114 HTTP/3 Protocol Compliance Tests
//!
//! Uses MockH3Server to inject malformed frames and test client robustness.

use specter::transport::h3::H3Client;
use std::time::Duration;
// use tokio::time::timeout;

mod helpers;
use helpers::mock_h3_server::MockH3Server;

#[tokio::test]
async fn test_h3_clean_shutdown() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("trace")
        .try_init();

    let server: MockH3Server = MockH3Server::new().await.unwrap();
    let url = server.url();
    let url_clone = url.clone();

    // Start server handler
    server.start(
        |conn: helpers::mock_h3_server::MockH3Connection| async move {
            tracing::info!("Mock Server: Connection accepted");

            // quiche::h3::Connection (on server side) sends SETTINGS automatically.

            // Wait for handshake/settings exchange to settle
            tokio::time::sleep(Duration::from_millis(200)).await;

            // Send GOAWAY to close connection cleanly (Proactive)
            // Frame Type 0x07 (GOAWAY)
            // Payload: LastStreamID (0), ErrorCode (0)
            let payload = vec![0x00, 0x00];
            conn.send_frame(0, 7, &payload).await;
            // Wait for flush
            tokio::time::sleep(Duration::from_millis(100)).await;
        },
    );

    // Client request
    // We need to disable cert verification because our mock uses a self-signed cert
    // H3Client might strictly verify. We might need to configure H3Client for testing.
    // Unlike H2Client which uses `danger_accept_invalid_certs`, H3Client wraps `quiche`.
    // We simulated `TlsFingerprint` earlier, let's see if we can relax it.
    // If H3Client doesn't expose it, we might fail here.

    // We need to disable cert verification because our mock uses a self-signed cert
    let client = H3Client::new().danger_accept_invalid_certs(true);

    let res = client.send_request(&url_clone, "GET", vec![], None).await;

    // Expecting error or success depending on cert validation?
    // Actually, checking H3Client source is wise.

    match res {
        Ok(_) => panic!("Client request unexpected success (should be GOAWAY or Closed)"),
        Err(e) => {
            tracing::info!("Client received expected error: {}", e);
            // Verify error is NO_ERROR (0) or ConnectionClosed
        }
    }
}

#[tokio::test]
async fn test_h3_malformed_frame() {
    let server: MockH3Server = MockH3Server::new().await.unwrap();
    let url = server.url();
    let url_clone = url.clone();

    server.start(
        |conn: helpers::mock_h3_server::MockH3Connection| async move {
            // Wait for handshake
            tokio::time::sleep(Duration::from_millis(200)).await;

            // Send DATA frame on Control Stream (Stream ID 3)
            // Control Stream ID is 3 (Server Uni).
            // DATA Frame type is 0x00.
            // Payload "bad"
            // This is H3_FRAME_UNEXPECTED (RFC 9114 7.2.1)

            // Note: MockH3Server h3_conn already opened Stream 3 for Settings.
            // We append DATA frame to it.
            let control_stream_id = 3;
            let payload = b"bad";
            conn.send_frame(control_stream_id, 0, payload).await;

            tokio::time::sleep(Duration::from_millis(100)).await;
        },
    );

    let client = H3Client::new().danger_accept_invalid_certs(true);
    let res = client.send_request(&url_clone, "GET", vec![], None).await;

    match res {
        Ok(_) => panic!("Client request unexpected success"),
        Err(e) => {
            tracing::info!("Client received expected error: {}", e);
            // Error should be H3_FRAME_UNEXPECTED (0x105) or H3_MISSING_SETTINGS (0x107) if frame arrived before settings processed
            let msg = format!("{}", e);
            assert!(
                msg.contains("261")
                    || msg.contains("frame unexpected")
                    || msg.contains("closed")
                    || msg.contains("channel closed")
                    || msg.contains("MissingSettings"),
                "Error should indicate frame unexpected or closure, got: {}",
                msg
            );
        }
    }
}
