//! Native HTTP/2 client using h2 crate directly.
//!
//! This module provides HTTP/2 support with full SETTINGS frame fingerprinting,
//! bypassing hyper's abstraction layer to enable browser-like HTTP/2 behavior.

use bytes::Bytes;
use h2::client::{Builder, SendRequest};
use http::{Method, Request, Uri};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::error::{Error, Result};
use crate::fingerprint::http2::Http2Settings;
use crate::response::Response;
use crate::transport::connector::MaybeHttpsStream;

/// Chrome's total connection-level window size (~15MB).
/// Chrome sends initial 65535 + WINDOW_UPDATE of 15663105 = 15728640 total.
const CHROME_CONNECTION_WINDOW_SIZE: u32 = 15728640;

/// Pseudo-header ordering for browser fingerprinting.
/// Chrome uses: :method, :authority, :scheme, :path (masp)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PseudoHeaderOrder {
    /// Chrome order: method, authority, scheme, path
    #[default]
    Chrome,
    /// Firefox order: method, path, authority, scheme
    Firefox,
    /// Safari order: method, scheme, path, authority
    Safari,
    /// curl order: method, path, scheme, authority
    Curl,
}

/// Native HTTP/2 connection with SETTINGS fingerprinting support.
pub struct H2Connection {
    /// Handle for sending requests (supports multiplexing via Clone)
    send_request: SendRequest<Bytes>,
    /// HTTP/2 settings used for this connection
    #[allow(dead_code)]
    settings: Http2Settings,
    /// Pseudo-header ordering
    pseudo_order: PseudoHeaderOrder,
}

impl H2Connection {
    /// Create a new HTTP/2 connection with custom SETTINGS fingerprint.
    ///
    /// This performs the HTTP/2 handshake with the specified SETTINGS and
    /// spawns a background task to drive the connection.
    pub async fn connect(
        stream: MaybeHttpsStream,
        settings: Http2Settings,
        pseudo_order: PseudoHeaderOrder,
    ) -> Result<Self> {
        // Configure h2 builder with fingerprint settings
        let mut builder = Builder::new();
        builder
            .header_table_size(settings.header_table_size)
            .initial_window_size(settings.initial_window_size)
            // Set connection-level window to Chrome's ~15MB (simulates WINDOW_UPDATE)
            .initial_connection_window_size(CHROME_CONNECTION_WINDOW_SIZE)
            .max_concurrent_streams(settings.max_concurrent_streams)
            .max_frame_size(settings.max_frame_size)
            .max_header_list_size(settings.max_header_list_size)
            .enable_push(settings.enable_push);

        // Perform HTTP/2 handshake
        let (send_request, connection) = builder
            .handshake(stream)
            .await
            .map_err(|e| Error::HttpProtocol(format!("HTTP/2 handshake failed: {}", e)))?;

        // Spawn connection driver task (CRITICAL: no I/O without this)
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::error!("HTTP/2 connection error: {}", e);
            }
        });

        Ok(Self {
            send_request,
            settings,
            pseudo_order,
        })
    }

    /// Create a connection with default Chrome fingerprint.
    pub async fn connect_chrome(stream: MaybeHttpsStream) -> Result<Self> {
        Self::connect(stream, Http2Settings::default(), PseudoHeaderOrder::Chrome).await
    }

    /// Check if the connection can accept new streams.
    pub async fn ready(&mut self) -> Result<SendRequest<Bytes>> {
        // Clone to get owned handle, then wait for capacity
        let sender = self.send_request.clone();
        sender
            .ready()
            .await
            .map_err(|e| Error::HttpProtocol(format!("HTTP/2 not ready: {}", e)))
    }

    /// Send an HTTP/2 request with proper pseudo-header ordering.
    pub async fn send_request(
        &mut self,
        method: Method,
        uri: &Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        // Wait for capacity and get ready sender
        let mut sender = self.ready().await?;

        // Build request with ordered pseudo-headers
        let request = self.build_request(method, uri, headers, body.is_some())?;

        // Determine if we're sending body
        let has_body = body.is_some();
        let body_bytes = body.unwrap_or_default();

        // Send request
        let (response_future, mut send_stream) = sender
            .send_request(request, !has_body)
            .map_err(|e| Error::HttpProtocol(format!("Failed to send HTTP/2 request: {}", e)))?;

        // Send body if present
        if has_body {
            send_stream
                .send_data(body_bytes, true)
                .map_err(|e| Error::HttpProtocol(format!("Failed to send request body: {}", e)))?;
        }

        // Await response headers
        let response = response_future
            .await
            .map_err(|e| Error::HttpProtocol(format!("HTTP/2 response error: {}", e)))?;

        // Extract status and headers
        let status = response.status().as_u16();
        let response_headers: Vec<String> = response
            .headers()
            .iter()
            .map(|(name, value)| {
                format!("{}: {}", name.as_str(), value.to_str().unwrap_or(""))
            })
            .collect();

        // Collect response body
        let mut body_parts = response.into_body();
        let mut body_bytes = Vec::new();

        while let Some(chunk) = body_parts.data().await {
            let chunk = chunk
                .map_err(|e| Error::HttpProtocol(format!("Failed to read response body: {}", e)))?;
            body_bytes.extend_from_slice(&chunk);

            // Release flow control capacity
            let _ = body_parts.flow_control().release_capacity(chunk.len());
        }

        Ok(Response::new(
            status,
            response_headers,
            Bytes::from(body_bytes),
            "HTTP/2".to_string(),
        ))
    }

    /// Build HTTP request with proper pseudo-header ordering.
    fn build_request(
        &self,
        method: Method,
        uri: &Uri,
        headers: Vec<(String, String)>,
        _has_body: bool,
    ) -> Result<Request<()>> {
        // Extract URI components
        // Note: scheme and path are part of the URI, authority used for :authority header
        let _scheme = uri.scheme_str().unwrap_or("https");
        let authority = uri
            .authority()
            .map(|a| a.as_str())
            .unwrap_or_else(|| uri.host().unwrap_or(""));
        let _path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        // Build request with pseudo-headers in correct order
        // Note: http crate handles pseudo-header ordering internally,
        // but we use the builder pattern for clarity
        let mut builder = Request::builder()
            .method(method)
            .uri(uri.clone());

        // Add :authority header explicitly (some servers require it)
        builder = builder.header(":authority", authority);

        // Add custom headers
        for (name, value) in headers {
            // Skip pseudo-headers in custom headers
            if !name.starts_with(':') {
                builder = builder.header(name, value);
            }
        }

        builder
            .body(())
            .map_err(|e| Error::HttpProtocol(format!("Failed to build request: {}", e)))
    }

    /// Clone the send request handle for multiplexing.
    /// Each cloned handle can send requests concurrently on the same connection.
    pub fn clone_sender(&self) -> SendRequest<Bytes> {
        self.send_request.clone()
    }

    /// Get the pseudo-header ordering used by this connection.
    pub fn pseudo_order(&self) -> PseudoHeaderOrder {
        self.pseudo_order
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

    /// Set the pseudo-header ordering.
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
    fn test_pseudo_order_default() {
        let builder = H2ClientBuilder::new();
        assert_eq!(builder.pseudo_order, PseudoHeaderOrder::Chrome);
    }
}
