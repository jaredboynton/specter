//! HTTP/2 fingerprint configuration (SETTINGS frame).

use std::time::Duration;

/// PRIORITY frame pattern for browser fingerprinting.
///
/// Different browsers send PRIORITY frames with different dependency trees.
/// Format: (stream_id, depends_on_stream_id, weight, exclusive)
/// - exclusive: true means this stream replaces all dependencies of the parent
/// - weight: 1-256, higher means more bandwidth allocation
#[derive(Debug, Clone)]
pub struct PriorityTree {
    /// Priority frames to send: (stream_id, depends_on, weight, exclusive)
    pub priorities: Vec<(u32, u32, u8, bool)>,
}

impl PriorityTree {
    /// Chrome PRIORITY frame pattern.
    ///
    /// Chrome sends PRIORITY frames for streams 3,5,7,9,11:
    /// - Stream 3: depends on 0 (root), weight 201
    /// - Stream 5: depends on 0 (root), weight 101
    /// - Stream 7: depends on 0 (root), weight 1
    /// - Stream 9: depends on 7, weight 1
    /// - Stream 11: depends on 3, weight 1
    ///
    /// Akamai format: `3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1`
    pub fn chrome() -> Self {
        Self {
            priorities: vec![
                (3, 0, 201, false), // High priority resource
                (5, 0, 101, false), // Medium priority resource
                (7, 0, 1, false),   // Low priority resource
                (9, 7, 1, false),   // Depends on stream 7
                (11, 3, 1, false),  // Depends on stream 3
            ],
        }
    }

    /// Firefox PRIORITY frame pattern.
    ///
    /// Firefox sends PRIORITY frames for streams that haven't been opened yet,
    /// establishing a dependency tree for future streams. Firefox uses a different
    /// pattern than Chrome.
    ///
    /// The exact Firefox HTTP/2 fingerprint pattern requires verification against
    /// real browser traffic captures.
    /// This is a placeholder based on Firefox's known behavior of sending
    /// PRIORITY frames for unopened streams.
    pub fn firefox() -> Self {
        // Firefox typically sends fewer PRIORITY frames than Chrome
        // and uses different dependency patterns
        Self {
            priorities: vec![(3, 0, 201, false), (5, 0, 101, false), (7, 0, 1, false)],
        }
    }

    /// No PRIORITY frames (some clients don't send them).
    pub fn none() -> Self {
        Self {
            priorities: Vec::new(),
        }
    }
}

/// HTTP/2 SETTINGS for fingerprinting.
#[derive(Debug, Clone)]
pub struct Http2Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
    /// Initial connection-level WINDOW_UPDATE value sent after SETTINGS.
    /// Chrome: 15663105 (15MB), Firefox: 12517377 (12MB)
    pub initial_window_update: u32,
    /// Whether to send all 6 SETTINGS parameters (Chrome) or only selective ones (Firefox).
    /// Firefox only sends: HEADER_TABLE_SIZE (1), INITIAL_WINDOW_SIZE (4), MAX_FRAME_SIZE (5)
    pub send_all_settings: bool,
    /// PRIORITY frame pattern to send during connection setup.
    /// Chrome sends PRIORITY frames for streams 3,5,7,9,11.
    /// Firefox sends different PRIORITY patterns.
    pub priority_tree: Option<PriorityTree>,
    /// PING frame interval for connection keep-alive.
    /// Chrome sends PING frames approximately every 45 seconds.
    /// Set to None to disable automatic PING frames.
    pub ping_interval: Option<Duration>,
    /// Handshake timeout for waiting for server SETTINGS frame.
    /// Default: 10 seconds (matches h2 crate behavior).
    /// Set to None for no timeout (not recommended for production).
    pub handshake_timeout: Option<Duration>,
}

impl Default for Http2Settings {
    fn default() -> Self {
        // Chrome defaults
        Self {
            header_table_size: 65536,
            enable_push: false,
            max_concurrent_streams: 1000,
            initial_window_size: 6291456,
            max_frame_size: 16384,
            max_header_list_size: 262144,
            initial_window_update: 15663105, // Chrome's 15MB window update
            send_all_settings: true,         // Chrome sends all 6 settings
            priority_tree: Some(PriorityTree::chrome()), // Chrome sends PRIORITY frames
            ping_interval: Some(Duration::from_secs(45)), // Chrome sends PING ~every 45s
            handshake_timeout: Some(Duration::from_secs(10)),
        }
    }
}

impl Http2Settings {
    /// Create Firefox 133 HTTP/2 settings.
    ///
    /// Firefox differs from Chrome:
    /// - HEADER_TABLE_SIZE: 65536 (same)
    /// - ENABLE_PUSH: not sent (omitted from SETTINGS frame)
    /// - MAX_CONCURRENT_STREAMS: not sent (omitted, defaults to unlimited)
    /// - INITIAL_WINDOW_SIZE: 131072 (128KB, vs Chrome's 6MB)
    /// - MAX_FRAME_SIZE: 16384 (same)
    /// - MAX_HEADER_LIST_SIZE: not sent (omitted)
    ///
    /// Expected Firefox Akamai SETTINGS: `1:65536;4:131072;5:16384`
    /// Expected Firefox WINDOW_UPDATE: `12517377` (vs Chrome's 15663105)
    pub fn firefox() -> Self {
        Self {
            header_table_size: 65536,
            enable_push: true, // Firefox enables push, but doesn't send in SETTINGS
            max_concurrent_streams: 100, // Firefox default, but not sent in SETTINGS
            initial_window_size: 131072, // 128KB (desktop), vs Chrome's 6MB
            max_frame_size: 16384,
            max_header_list_size: 0, // Not sent in Firefox SETTINGS frame
            initial_window_update: 12517377, // Firefox's 12MB window update
            send_all_settings: false, // Firefox only sends 3 settings (1, 4, 5)
            priority_tree: Some(PriorityTree::firefox()), // Firefox sends PRIORITY frames
            ping_interval: Some(Duration::from_secs(30)), // Firefox sends PING ~every 30s
            handshake_timeout: Some(Duration::from_secs(10)),
        }
    }
}
