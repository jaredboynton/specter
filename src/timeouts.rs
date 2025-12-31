//! Timeout configuration for HTTP requests.
//!
//! Provides granular timeout control matching production best practices from
//! reqwest, curl, httpx, and aiohttp.
//!
//! # Timeout Types
//!
//! - **connect**: TCP + TLS/QUIC handshake timeout
//! - **ttfb**: Time-to-first-byte (request sent → response headers received)
//! - **read_idle**: Maximum time between received bytes (resets on each chunk)
//! - **write_idle**: Maximum time between sent bytes (for uploads)
//! - **total**: Absolute deadline for entire request lifecycle
//! - **pool_acquire**: Time to wait for a pooled connection
//!
//! # Usage
//!
//! ```rust,ignore
//! use specter::{Client, Timeouts};
//! use std::time::Duration;
//!
//! // For normal API calls
//! let client = Client::builder()
//!     .timeouts(Timeouts::api_defaults())
//!     .build()?;
//!
//! // For streaming (SSE, etc.)
//! let client = Client::builder()
//!     .timeouts(Timeouts::streaming_defaults())
//!     .build()?;
//!
//! // Custom configuration
//! let client = Client::builder()
//!     .connect_timeout(Duration::from_secs(5))
//!     .ttfb_timeout(Duration::from_secs(30))
//!     .read_timeout(Duration::from_secs(60))
//!     .build()?;
//! ```

use std::time::Duration;

/// Timeout configuration for HTTP requests.
///
/// All timeouts are optional. When `None`, no timeout is applied for that phase.
///
/// # Timeout Semantics
///
/// - **connect**: Does NOT reset. Deadline for establishing transport connection.
/// - **ttfb**: Does NOT reset. Deadline from request sent to headers received.
/// - **read_idle**: RESETS on each chunk received. Detects hung streams.
/// - **write_idle**: RESETS on each chunk sent. Detects hung uploads.
/// - **total**: Does NOT reset. Absolute deadline for entire request.
/// - **pool_acquire**: Does NOT reset. Time waiting for pooled connection.
#[derive(Clone, Debug, Default)]
pub struct Timeouts {
    /// Timeout for establishing connection (DNS + TCP + TLS/QUIC handshake).
    ///
    /// Default: 10s for api_defaults(), 10s for streaming_defaults()
    pub connect: Option<Duration>,

    /// Time-to-first-byte timeout: time from request sent until response headers received.
    ///
    /// This is the "server responsiveness" timeout - detects servers that accept
    /// connections but hang before responding.
    ///
    /// Default: 30s for api_defaults(), 30s for streaming_defaults()
    pub ttfb: Option<Duration>,

    /// Read idle timeout: maximum time waiting for next chunk of response body.
    ///
    /// **This timeout resets on each successful read.** It detects hung streams
    /// without killing healthy long-running transfers.
    ///
    /// For SSE/streaming, this is typically your primary timeout mechanism.
    ///
    /// Default: 30s for api_defaults(), 120s for streaming_defaults()
    pub read_idle: Option<Duration>,

    /// Write idle timeout: maximum time waiting to send next chunk of request body.
    ///
    /// **This timeout resets on each successful write.** Useful for large uploads.
    ///
    /// Default: 30s for both presets
    pub write_idle: Option<Duration>,

    /// Total request deadline: absolute time limit for entire request lifecycle.
    ///
    /// **This timeout does NOT reset.** It caps connect + request + response.
    ///
    /// For streaming responses, you typically want this disabled (None) and
    /// rely on read_idle instead.
    ///
    /// Default: 120s for api_defaults(), None for streaming_defaults()
    pub total: Option<Duration>,

    /// Pool acquire timeout: time waiting for an available pooled connection.
    ///
    /// Under high load, this prevents requests from queueing indefinitely.
    ///
    /// Default: 5s for both presets
    pub pool_acquire: Option<Duration>,
}

impl Timeouts {
    /// Create a new Timeouts with all timeouts set to None.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sensible defaults for normal API calls.
    ///
    /// - connect: 10s
    /// - ttfb: 30s
    /// - read_idle: 30s
    /// - write_idle: 30s
    /// - total: 120s
    /// - pool_acquire: 5s
    pub fn api_defaults() -> Self {
        Self {
            connect: Some(Duration::from_secs(10)),
            ttfb: Some(Duration::from_secs(30)),
            read_idle: Some(Duration::from_secs(30)),
            write_idle: Some(Duration::from_secs(30)),
            total: Some(Duration::from_secs(120)),
            pool_acquire: Some(Duration::from_secs(5)),
        }
    }

    /// Sensible defaults for streaming responses (SSE, chunked downloads, etc.).
    ///
    /// Key differences from api_defaults():
    /// - total: None (streams can run indefinitely)
    /// - read_idle: 120s (longer to accommodate variable chunk timing)
    ///
    /// - connect: 10s
    /// - ttfb: 30s
    /// - read_idle: 120s
    /// - write_idle: 30s
    /// - total: None
    /// - pool_acquire: 5s
    pub fn streaming_defaults() -> Self {
        Self {
            connect: Some(Duration::from_secs(10)),
            ttfb: Some(Duration::from_secs(30)),
            read_idle: Some(Duration::from_secs(120)),
            write_idle: Some(Duration::from_secs(30)),
            total: None, // Streams can run indefinitely
            pool_acquire: Some(Duration::from_secs(5)),
        }
    }

    /// Set connect timeout.
    pub fn connect(mut self, timeout: Duration) -> Self {
        self.connect = Some(timeout);
        self
    }

    /// Set TTFB (time-to-first-byte) timeout.
    pub fn ttfb(mut self, timeout: Duration) -> Self {
        self.ttfb = Some(timeout);
        self
    }

    /// Set read idle timeout.
    pub fn read_idle(mut self, timeout: Duration) -> Self {
        self.read_idle = Some(timeout);
        self
    }

    /// Set write idle timeout.
    pub fn write_idle(mut self, timeout: Duration) -> Self {
        self.write_idle = Some(timeout);
        self
    }

    /// Set total request deadline.
    pub fn total(mut self, timeout: Duration) -> Self {
        self.total = Some(timeout);
        self
    }

    /// Set pool acquire timeout.
    pub fn pool_acquire(mut self, timeout: Duration) -> Self {
        self.pool_acquire = Some(timeout);
        self
    }

    /// Disable connect timeout.
    pub fn no_connect_timeout(mut self) -> Self {
        self.connect = None;
        self
    }

    /// Disable TTFB timeout.
    pub fn no_ttfb_timeout(mut self) -> Self {
        self.ttfb = None;
        self
    }

    /// Disable read idle timeout.
    pub fn no_read_idle_timeout(mut self) -> Self {
        self.read_idle = None;
        self
    }

    /// Disable write idle timeout.
    pub fn no_write_idle_timeout(mut self) -> Self {
        self.write_idle = None;
        self
    }

    /// Disable total timeout.
    pub fn no_total_timeout(mut self) -> Self {
        self.total = None;
        self
    }

    /// Disable pool acquire timeout.
    pub fn no_pool_acquire_timeout(mut self) -> Self {
        self.pool_acquire = None;
        self
    }
}

/// Receive from a channel with idle timeout.
///
/// This is a utility for streaming responses. The timeout resets on each
/// successful receive, making it suitable for detecting hung streams without
/// killing healthy long-running transfers.
///
/// # Example
///
/// ```rust,ignore
/// use specter::timeouts::recv_with_idle_timeout;
/// use std::time::Duration;
///
/// let idle_timeout = Duration::from_secs(60);
/// while let Some(chunk) = recv_with_idle_timeout(&mut rx, idle_timeout).await? {
///     // Process chunk...
/// }
/// ```
pub async fn recv_with_idle_timeout<T>(
    rx: &mut tokio::sync::mpsc::Receiver<T>,
    idle: Duration,
) -> crate::Result<Option<T>> {
    tokio::select! {
        biased;
        v = rx.recv() => Ok(v),
        _ = tokio::time::sleep(idle) => Err(crate::Error::ReadIdleTimeout(idle)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_defaults() {
        let t = Timeouts::api_defaults();
        assert_eq!(t.connect, Some(Duration::from_secs(10)));
        assert_eq!(t.ttfb, Some(Duration::from_secs(30)));
        assert_eq!(t.read_idle, Some(Duration::from_secs(30)));
        assert_eq!(t.total, Some(Duration::from_secs(120)));
    }

    #[test]
    fn test_streaming_defaults() {
        let t = Timeouts::streaming_defaults();
        assert_eq!(t.connect, Some(Duration::from_secs(10)));
        assert_eq!(t.ttfb, Some(Duration::from_secs(30)));
        assert_eq!(t.read_idle, Some(Duration::from_secs(120)));
        assert_eq!(t.total, None); // Key difference
    }

    #[test]
    fn test_builder_pattern() {
        let t = Timeouts::new()
            .connect(Duration::from_secs(5))
            .ttfb(Duration::from_secs(15))
            .read_idle(Duration::from_secs(60));

        assert_eq!(t.connect, Some(Duration::from_secs(5)));
        assert_eq!(t.ttfb, Some(Duration::from_secs(15)));
        assert_eq!(t.read_idle, Some(Duration::from_secs(60)));
        assert_eq!(t.total, None);
    }
}
