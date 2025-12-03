//! Debug test to verify HTTP/2 frame serialization
//!
//! Run with: cargo test --test h2_frames_debug -- --nocapture

use specter::transport::h2::{
    FrameHeader, FrameType, WindowUpdateFrame, CHROME_WINDOW_UPDATE, CONNECTION_PREFACE,
};
use tracing::info;

#[test]
fn test_window_update_frame() {
    let wu = WindowUpdateFrame::new(0, CHROME_WINDOW_UPDATE);
    let bytes = wu.serialize();

    info!("WINDOW_UPDATE frame ({} bytes):", bytes.len());
    info!("Hex: {}", hex::encode(&bytes));

    // Frame should be: 9-byte header + 4 bytes payload
    assert_eq!(bytes.len(), 13, "WINDOW_UPDATE frame should be 13 bytes");

    let header = FrameHeader::parse(&bytes[..9]).expect("Should parse frame header");
    assert_eq!(header.frame_type, FrameType::WindowUpdate);
    assert_eq!(header.length, 4);
    assert_eq!(header.stream_id, 0);

    // Parse increment value
    let increment = u32::from_be_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]);
    info!(
        "Increment: {} (expected: {})",
        increment, CHROME_WINDOW_UPDATE
    );
    assert_eq!(increment, CHROME_WINDOW_UPDATE);
}

#[test]
fn test_connection_preface() {
    info!("Connection preface ({} bytes):", CONNECTION_PREFACE.len());
    info!("Hex: {}", hex::encode(CONNECTION_PREFACE));
    info!("ASCII: {}", String::from_utf8_lossy(CONNECTION_PREFACE));

    // RFC 9113: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    assert_eq!(CONNECTION_PREFACE.len(), 24);
    assert_eq!(&CONNECTION_PREFACE[..16], b"PRI * HTTP/2.0\r\n");
}
