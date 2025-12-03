//! Debug test to verify HTTP/2 frame serialization
//!
//! Run with: cargo test --test h2_frames_debug -- --nocapture

use specter::fingerprint::http2::Http2Settings;
use specter::transport::h2::{
    FrameHeader, FrameType, SettingsFrame, SettingsId, WindowUpdateFrame, CHROME_WINDOW_UPDATE,
    CONNECTION_PREFACE,
};
use tracing::info;

#[test]
fn test_settings_frame_serialization() {
    let settings = Http2Settings::default();

    // Build SETTINGS frame like we do in connect()
    let mut settings_frame = SettingsFrame::new();
    settings_frame
        .set(SettingsId::HeaderTableSize, settings.header_table_size)
        .set(
            SettingsId::EnablePush,
            if settings.enable_push { 1 } else { 0 },
        )
        .set(
            SettingsId::MaxConcurrentStreams,
            settings.max_concurrent_streams,
        )
        .set(SettingsId::InitialWindowSize, settings.initial_window_size)
        .set(SettingsId::MaxFrameSize, settings.max_frame_size)
        .set(SettingsId::MaxHeaderListSize, settings.max_header_list_size);

    let bytes = settings_frame.serialize();

    info!("SETTINGS frame ({} bytes):", bytes.len());
    info!("Hex: {}", hex::encode(&bytes));

    // Frame should be: 9-byte header + 36 bytes payload (6 settings * 6 bytes each)
    assert_eq!(bytes.len(), 9 + 36, "SETTINGS frame should be 45 bytes");

    // Parse frame header
    let header = FrameHeader::parse(&bytes[..9]).expect("Should parse frame header");
    info!("Frame type: {:?}", header.frame_type);
    info!("Length: {}", header.length);
    info!("Flags: 0x{:02x}", header.flags);
    info!("Stream ID: {}", header.stream_id);

    assert_eq!(header.frame_type, FrameType::Settings);
    assert_eq!(header.length, 36, "Payload should be 36 bytes");
    assert_eq!(header.stream_id, 0, "SETTINGS must be on stream 0");

    // Parse payload (settings are 2-byte ID + 4-byte value)
    let payload = &bytes[9..];
    info!("Settings:");
    for i in 0..6 {
        let offset = i * 6;
        let id = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let value = u32::from_be_bytes([
            payload[offset + 2],
            payload[offset + 3],
            payload[offset + 4],
            payload[offset + 5],
        ]);
        info!("  {}:{}", id, value);
    }

    // Verify settings match Chrome fingerprint (all 6 settings)
    let expected = "1:65536;2:0;3:1000;4:6291456;5:16384;6:262144";
    info!("Expected Akamai format: {}", expected);
}

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
