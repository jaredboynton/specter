//! Error types for specter crate.

use std::io;

/// Result type alias using our Error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during HTTP operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// HTTP protocol error.
    #[error("HTTP protocol error: {0}")]
    HttpProtocol(String),

    /// Invalid HTTP status code.
    #[error("HTTP {status}: {message}")]
    HttpStatus { status: u16, message: String },

    /// Redirect limit exceeded.
    #[error("Redirect limit exceeded ({count} redirects)")]
    RedirectLimit { count: u32 },

    /// Invalid redirect URL.
    #[error("Invalid redirect URL: {0}")]
    InvalidRedirectUrl(String),

    /// Cookie parsing error.
    #[error("Cookie parse error: {0}")]
    CookieParse(String),

    /// Decompression error.
    #[error("Decompression error: {0}")]
    Decompression(String),

    /// URL parsing error.
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Missing required field or data.
    #[error("Missing required: {0}")]
    Missing(String),

    /// Generic timeout error.
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Connect timeout (TCP + TLS handshake).
    #[error("Connect timeout after {0:?}")]
    ConnectTimeout(std::time::Duration),

    /// TTFB (time-to-first-byte) timeout.
    #[error("TTFB timeout after {0:?} - server did not respond with headers")]
    TtfbTimeout(std::time::Duration),

    /// Read idle timeout (no data received within duration).
    #[error("Read idle timeout after {0:?} - stream may be hung")]
    ReadIdleTimeout(std::time::Duration),

    /// Write idle timeout (could not send data within duration).
    #[error("Write idle timeout after {0:?}")]
    WriteIdleTimeout(std::time::Duration),

    /// Total request deadline exceeded.
    #[error("Total request deadline exceeded after {0:?}")]
    TotalTimeout(std::time::Duration),

    /// Pool acquire timeout (no connection available).
    #[error("Pool acquire timeout after {0:?} - no connections available")]
    PoolAcquireTimeout(std::time::Duration),

    /// Connection error.
    #[error("Connection error: {0}")]
    Connection(String),

    /// TLS/SSL error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// QUIC/HTTP3 error.
    #[error("QUIC error: {0}")]
    Quic(String),

    /// HTTP/2 SETTINGS_TIMEOUT error (RFC 9113 Section 7).
    #[error("SETTINGS_TIMEOUT (0x04): No SETTINGS frame received within {0:?}")]
    SettingsTimeout(std::time::Duration),
}

impl Error {
    /// Create an HTTP status error.
    pub fn http_status(status: u16, message: impl Into<String>) -> Self {
        Self::HttpStatus {
            status,
            message: message.into(),
        }
    }

    /// Create a missing field error.
    pub fn missing(field: impl Into<String>) -> Self {
        Self::Missing(field.into())
    }

    /// Create an IO error with custom message.
    pub fn io(message: impl Into<String>) -> Self {
        Self::Io(io::Error::other(message.into()))
    }

    /// Create an HTTP protocol error.
    pub fn http_protocol(message: impl Into<String>) -> Self {
        Self::HttpProtocol(message.into())
    }

    /// Create a connection error.
    pub fn connection(message: impl Into<String>) -> Self {
        Self::Connection(message.into())
    }

    /// Create a timeout error.
    pub fn timeout(message: impl Into<String>) -> Self {
        Self::Timeout(message.into())
    }

    /// Create a TLS error.
    pub fn tls(message: impl Into<String>) -> Self {
        Self::Tls(message.into())
    }

    /// Create a QUIC error.
    pub fn quic(message: impl Into<String>) -> Self {
        Self::Quic(message.into())
    }
}
