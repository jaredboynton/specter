//! PRIORITY frame serialization and pattern tests.
//!
//! Validates PRIORITY frame generation for Chrome and Firefox fingerprinting.

use specter::fingerprint::http2::PriorityTree;
use specter::transport::h2::{FrameHeader, FrameType, PriorityFrame, FRAME_HEADER_SIZE};

#[test]
fn test_priority_tree_chrome() {
    let tree = PriorityTree::chrome();

    // Chrome sends 5 PRIORITY frames
    assert_eq!(tree.priorities.len(), 5);

    // Verify Chrome priority pattern
    assert_eq!(tree.priorities[0], (3, 0, 201, false)); // High priority
    assert_eq!(tree.priorities[1], (5, 0, 101, false)); // Medium priority
    assert_eq!(tree.priorities[2], (7, 0, 1, false)); // Low priority
    assert_eq!(tree.priorities[3], (9, 7, 1, false)); // Depends on stream 7
    assert_eq!(tree.priorities[4], (11, 3, 1, false)); // Depends on stream 3

    // Verify weights are valid (1-256, stored as 0-255 in u8)
    // Note: HTTP/2 weight is 1-256, but stored as weight-1 in u8 (0-255)
    for (_, _, weight, _) in &tree.priorities {
        assert!(*weight <= 255, "Weight must be <= 255 (represents 1-256)");
    }
}

#[test]
fn test_priority_tree_firefox() {
    let tree = PriorityTree::firefox();

    // Firefox sends 3 PRIORITY frames (fewer than Chrome)
    assert_eq!(tree.priorities.len(), 3);

    // Verify Firefox priority pattern
    assert_eq!(tree.priorities[0], (3, 0, 201, false));
    assert_eq!(tree.priorities[1], (5, 0, 101, false));
    assert_eq!(tree.priorities[2], (7, 0, 1, false));

    // Firefox doesn't send dependent priorities (9, 11) like Chrome
}

#[test]
fn test_priority_tree_none() {
    let tree = PriorityTree::none();
    assert_eq!(tree.priorities.len(), 0);
}

#[test]
fn test_priority_frame_serialization() {
    // Test Chrome priority frame for stream 3
    let frame = PriorityFrame::new(3, 0, 201, false);
    let bytes = frame.serialize();

    // PRIORITY frame: 9-byte header + 5-byte payload
    assert_eq!(
        bytes.len(),
        FRAME_HEADER_SIZE + 5,
        "PRIORITY frame should be 14 bytes"
    );

    // Parse frame header
    let header =
        FrameHeader::parse(&bytes[..FRAME_HEADER_SIZE]).expect("Should parse frame header");

    assert_eq!(header.frame_type, FrameType::Priority);
    assert_eq!(header.length, 5, "PRIORITY payload should be 5 bytes");
    assert_eq!(header.stream_id, 3);

    // Parse payload (RFC 9113 Section 6.3.2)
    let payload = &bytes[FRAME_HEADER_SIZE..];

    // First 4 bytes: stream dependency (31 bits) + exclusive flag (1 bit)
    let dep_and_exclusive = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

    let exclusive = (dep_and_exclusive & 0x80000000) != 0;
    let stream_dependency = dep_and_exclusive & 0x7FFFFFFF;

    assert!(!exclusive, "Chrome stream 3 should not be exclusive");
    assert_eq!(stream_dependency, 0, "Stream 3 depends on root (0)");

    // 5th byte: weight (HTTP/2 spec says weight is 1-256, stored as weight-1, so 0-255)
    // But our PriorityFrame stores it directly (201), not as weight-1
    let weight_value = payload[4] as u8;
    // PriorityFrame stores weight directly, not as weight-1
    assert_eq!(weight_value, 201, "Weight should be 201 (stored directly)");
}

#[test]
fn test_priority_frame_with_dependency() {
    // Test Chrome priority frame for stream 9 (depends on stream 7)
    let frame = PriorityFrame::new(9, 7, 1, false);
    let bytes = frame.serialize();

    let payload = &bytes[FRAME_HEADER_SIZE..];
    let dep_and_exclusive = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

    let exclusive = (dep_and_exclusive & 0x80000000) != 0;
    let stream_dependency = dep_and_exclusive & 0x7FFFFFFF;

    assert!(!exclusive);
    assert_eq!(stream_dependency, 7, "Stream 9 should depend on stream 7");

    let weight = payload[4] as u8;
    assert_eq!(weight, 1, "Weight should be 1 (stored directly)");
}

#[test]
fn test_priority_frame_exclusive() {
    // Test exclusive priority (E bit set)
    let frame = PriorityFrame::new(5, 3, 100, true);
    let bytes = frame.serialize();

    let payload = &bytes[FRAME_HEADER_SIZE..];
    let dep_and_exclusive = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

    let exclusive = (dep_and_exclusive & 0x80000000) != 0;
    let stream_dependency = dep_and_exclusive & 0x7FFFFFFF;

    assert!(exclusive, "E bit should be set");
    assert_eq!(stream_dependency, 3);
}

#[test]
fn test_priority_tree_in_http2_settings() {
    use specter::fingerprint::http2::Http2Settings;

    // Chrome settings include PRIORITY tree
    let chrome_settings = Http2Settings::default();
    assert!(chrome_settings.priority_tree.is_some());
    let chrome_tree = chrome_settings.priority_tree.as_ref().unwrap();
    assert_eq!(chrome_tree.priorities.len(), 5);

    // Firefox settings include PRIORITY tree
    let firefox_settings = Http2Settings::firefox();
    assert!(firefox_settings.priority_tree.is_some());
    let firefox_tree = firefox_settings.priority_tree.as_ref().unwrap();
    assert_eq!(firefox_tree.priorities.len(), 3);
}

#[test]
fn test_priority_akamai_format() {
    // Chrome Akamai format: 3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1
    // Format: stream:exclusive:dependency:weight
    let chrome_tree = PriorityTree::chrome();

    let mut akamai_parts = Vec::new();
    for (stream_id, depends_on, weight, exclusive) in &chrome_tree.priorities {
        let exclusive_val = if *exclusive { 1 } else { 0 };
        akamai_parts.push(format!(
            "{}:{}:{}:{}",
            stream_id, exclusive_val, depends_on, weight
        ));
    }

    let akamai_str = akamai_parts.join(",");

    // Verify format matches expected Chrome pattern
    assert!(akamai_str.contains("3:0:0:201"));
    assert!(akamai_str.contains("5:0:0:101"));
    assert!(akamai_str.contains("7:0:0:1"));
    assert!(akamai_str.contains("9:0:7:1"));
    assert!(akamai_str.contains("11:0:3:1"));
}
