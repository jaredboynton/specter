//! HTTP/2 fingerprint configuration (SETTINGS frame).

/// HTTP/2 SETTINGS for fingerprinting.
#[derive(Debug, Clone)]
pub struct Http2Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
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
        }
    }
}
