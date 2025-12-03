//! HTTP version configuration.

/// HTTP version preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpVersion {
    /// Force HTTP/1.1.
    Http1_1,
    /// Attempt HTTP/2, fallback to HTTP/1.1.
    Http2,
    /// Attempt HTTP/3, fallback to HTTP/2, fallback to HTTP/1.1.
    #[default]
    Http3,
    /// HTTP/3 only, no fallback.
    Http3Only,
    /// Let the client decide based on server support.
    Auto,
}

impl HttpVersion {
    /// Get human-readable version string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http1_1 => "HTTP/1.1",
            Self::Http2 => "HTTP/2",
            Self::Http3 => "HTTP/3",
            Self::Http3Only => "HTTP/3 (no fallback)",
            Self::Auto => "Auto",
        }
    }

    /// Check if this version supports multiplexing.
    pub fn supports_multiplexing(&self) -> bool {
        matches!(
            self,
            Self::Http2 | Self::Http3 | Self::Http3Only | Self::Auto
        )
    }
}
