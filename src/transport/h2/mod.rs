//! Custom HTTP/2 implementation with full fingerprint control.
//!
//! This module provides HTTP/2 support with complete control over:
//! - **Pseudo-header ordering**: Chrome uses `:method, :scheme, :authority, :path` (m,s,a,p)
//! - **SETTINGS frame ordering**: Full control over parameter order
//! - **WINDOW_UPDATE behavior**: Chrome sends immediate 15MB window update
//!
//! Unlike the h2 crate which hardcodes these behaviors, this implementation
//! allows accurate browser fingerprint emulation.
//!
//! ## Akamai HTTP/2 Fingerprint Format
//!
//! The Akamai fingerprint format is: `settings|window_update|priority|pseudo_headers`
//!
//! Chrome 120+ example: `1:65536;2:0;3:1000;4:6291456;5:16384;6:262144|15663105|0|m,s,a,p`
//!
//! ## Usage
//!
//! ```no_run
//! use specter::transport::h2::{H2Connection, PseudoHeaderOrder};
//! use specter::fingerprint::http2::Http2Settings;
//! use specter::transport::connector::MaybeHttpsStream;
//! use http::{Method, Uri};
//!
//! # async fn example(stream: MaybeHttpsStream) -> Result<(), Box<dyn std::error::Error>> {
//! # let uri: Uri = "https://example.com".parse()?;
//! # let headers = vec![];
//! let settings = Http2Settings::default(); // Chrome settings
//! let mut conn = H2Connection::connect(stream, settings, PseudoHeaderOrder::Chrome).await?;
//! let response = conn.send_request(Method::GET, &uri, headers, None).await?;
//! # Ok(())
//! # }
//! ```

mod connection;
mod frame;
mod hpack;
mod hpack_impl;

pub use connection::{H2Connection as RawH2Connection, H2Error, StreamResponse, CHROME_WINDOW_UPDATE};
pub use frame::{
    flags, DataFrame, ErrorCode, FrameHeader, FrameType, GoAwayFrame, HeadersFrame, PingFrame,
    PriorityData, PriorityFrame, PushPromiseFrame, RstStreamFrame, SettingsFrame, SettingsId,
    WindowUpdateFrame, CONNECTION_PREFACE, DEFAULT_MAX_FRAME_SIZE, FRAME_HEADER_SIZE,
};
pub use hpack::{HpackDecoder, HpackEncoder, PseudoHeaderOrder};

// Re-export wrapper types for convenience
use bytes::Bytes;
use http::{Method, Uri};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::error::Result;
use crate::fingerprint::http2::Http2Settings;
use crate::response::Response;
use crate::transport::connector::MaybeHttpsStream;

/// Native HTTP/2 connection with full fingerprint control.
pub struct H2Connection {
    /// Inner connection (type-erased via trait object pattern)
    inner: RawH2Connection<MaybeHttpsStream>,
    /// HTTP/2 settings used for this connection
    settings: Http2Settings,
    /// Pseudo-header order
    pseudo_order: PseudoHeaderOrder,
}

impl H2Connection {
    /// Create a new HTTP/2 connection with custom fingerprint.
    ///
    /// This performs the HTTP/2 handshake with the specified SETTINGS and
    /// pseudo-header ordering for accurate browser fingerprint emulation.
    pub async fn connect(
        stream: MaybeHttpsStream,
        settings: Http2Settings,
        pseudo_order: PseudoHeaderOrder,
    ) -> Result<Self> {
        let inner = RawH2Connection::connect(stream, settings.clone(), pseudo_order).await?;

        Ok(Self {
            inner,
            settings,
            pseudo_order,
        })
    }

    /// Create a connection with default Chrome fingerprint.
    pub async fn connect_chrome(stream: MaybeHttpsStream) -> Result<Self> {
        Self::connect(stream, Http2Settings::default(), PseudoHeaderOrder::Chrome).await
    }

    /// Send an HTTP/2 request.
    pub async fn send_request(
        &mut self,
        method: Method,
        uri: &Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        self.inner.send_request(method, uri, headers, body).await
    }

    /// Get the pseudo-header order.
    pub fn pseudo_order(&self) -> PseudoHeaderOrder {
        self.pseudo_order
    }

    /// Get the settings.
    pub fn settings(&self) -> &Http2Settings {
        &self.settings
    }
}

/// HTTP/2 connection pool entry with multiplexing support.
pub struct H2PooledConnection {
    inner: Arc<Mutex<H2Connection>>,
}

impl H2PooledConnection {
    /// Create a new pooled connection.
    pub fn new(conn: H2Connection) -> Self {
        Self {
            inner: Arc::new(Mutex::new(conn)),
        }
    }

    /// Send a request using this pooled connection.
    pub async fn send_request(
        &self,
        method: Method,
        uri: &Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        let mut conn = self.inner.lock().await;
        conn.send_request(method, uri, headers, body).await
    }

    /// Clone this pooled connection handle.
    /// Multiple handles can use the same underlying HTTP/2 connection.
    pub fn clone_handle(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Clone for H2PooledConnection {
    fn clone(&self) -> Self {
        self.clone_handle()
    }
}

/// Builder for creating HTTP/2 connections with fingerprinting.
pub struct H2ClientBuilder {
    settings: Http2Settings,
    pseudo_order: PseudoHeaderOrder,
}

impl H2ClientBuilder {
    /// Create a new builder with default Chrome settings.
    pub fn new() -> Self {
        Self {
            settings: Http2Settings::default(),
            pseudo_order: PseudoHeaderOrder::Chrome,
        }
    }

    /// Set custom HTTP/2 settings.
    pub fn settings(mut self, settings: Http2Settings) -> Self {
        self.settings = settings;
        self
    }

    /// Set pseudo-header ordering for HTTP/2 fingerprinting.
    pub fn pseudo_order(mut self, order: PseudoHeaderOrder) -> Self {
        self.pseudo_order = order;
        self
    }

    /// Set header table size (SETTINGS_HEADER_TABLE_SIZE).
    pub fn header_table_size(mut self, size: u32) -> Self {
        self.settings.header_table_size = size;
        self
    }

    /// Set initial window size (SETTINGS_INITIAL_WINDOW_SIZE).
    pub fn initial_window_size(mut self, size: u32) -> Self {
        self.settings.initial_window_size = size;
        self
    }

    /// Set max concurrent streams (SETTINGS_MAX_CONCURRENT_STREAMS).
    pub fn max_concurrent_streams(mut self, max: u32) -> Self {
        self.settings.max_concurrent_streams = max;
        self
    }

    /// Set max frame size (SETTINGS_MAX_FRAME_SIZE).
    pub fn max_frame_size(mut self, size: u32) -> Self {
        self.settings.max_frame_size = size;
        self
    }

    /// Set max header list size (SETTINGS_MAX_HEADER_LIST_SIZE).
    pub fn max_header_list_size(mut self, size: u32) -> Self {
        self.settings.max_header_list_size = size;
        self
    }

    /// Set enable push (SETTINGS_ENABLE_PUSH).
    pub fn enable_push(mut self, enable: bool) -> Self {
        self.settings.enable_push = enable;
        self
    }

    /// Connect to a server using an existing TLS stream.
    pub async fn connect(self, stream: MaybeHttpsStream) -> Result<H2Connection> {
        H2Connection::connect(stream, self.settings, self.pseudo_order).await
    }

    /// Get the configured settings.
    pub fn get_settings(&self) -> &Http2Settings {
        &self.settings
    }

    /// Get the configured pseudo-header order.
    pub fn get_pseudo_order(&self) -> PseudoHeaderOrder {
        self.pseudo_order
    }
}

impl Default for H2ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings_match_chrome() {
        let settings = Http2Settings::default();
        assert_eq!(settings.header_table_size, 65536);
        assert_eq!(settings.initial_window_size, 6291456);
        assert_eq!(settings.max_concurrent_streams, 1000);
        assert_eq!(settings.max_frame_size, 16384);
        assert_eq!(settings.max_header_list_size, 262144);
        assert!(!settings.enable_push);
    }

    #[test]
    fn test_builder_settings() {
        let builder = H2ClientBuilder::new()
            .header_table_size(4096)
            .initial_window_size(65535)
            .max_concurrent_streams(100);

        assert_eq!(builder.settings.header_table_size, 4096);
        assert_eq!(builder.settings.initial_window_size, 65535);
        assert_eq!(builder.settings.max_concurrent_streams, 100);
    }

    #[test]
    fn test_builder_pseudo_order() {
        let builder = H2ClientBuilder::new();
        assert_eq!(builder.pseudo_order, PseudoHeaderOrder::Chrome);

        let builder = builder.pseudo_order(PseudoHeaderOrder::Firefox);
        assert_eq!(builder.pseudo_order, PseudoHeaderOrder::Firefox);
    }

    #[test]
    fn test_pseudo_order_akamai_strings() {
        assert_eq!(PseudoHeaderOrder::Chrome.akamai_string(), "m,s,a,p");
        assert_eq!(PseudoHeaderOrder::Firefox.akamai_string(), "m,p,a,s");
        assert_eq!(PseudoHeaderOrder::Safari.akamai_string(), "m,s,p,a");
        assert_eq!(PseudoHeaderOrder::Standard.akamai_string(), "m,a,s,p");
    }
}
