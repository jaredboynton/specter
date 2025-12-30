//! Unified HTTP/1.1, HTTP/2, and HTTP/3 client.
//!
//! Uses:
//! - h1.rs for HTTP/1.1 (minimal httparse-based implementation)
//! - h2.rs for HTTP/2 (with full SETTINGS fingerprinting and connection pooling)
//! - h3.rs for HTTP/3 (via quiche QUIC)
//!
//! Supports automatic HTTP/3 upgrade via Alt-Svc header caching.

use bytes::Bytes;
use http::{Method, Uri};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::timeout as tokio_timeout;

use crate::error::{Error, Result};
use crate::fingerprint::{http2::Http2Settings, FingerprintProfile};
use crate::pool::alt_svc::AltSvcCache;
use crate::pool::multiplexer::{ConnectionPool, PoolKey};
use crate::response::Response;
use crate::transport::connector::{BoringConnector, MaybeHttpsStream};
use crate::transport::h1::H1Connection;
use crate::transport::h2::{H2Connection, H2PooledConnection, PseudoHeaderOrder};
use crate::transport::h3::H3Client;
use crate::version::HttpVersion;

/// Unified HTTP client with HTTP/1.1, HTTP/2, and HTTP/3 support.
///
/// Provides automatic protocol selection based on ALPN negotiation and
/// Alt-Svc header caching for HTTP/3 upgrades.
///
/// HTTP/2 connections are pooled and multiplexed - multiple concurrent requests
/// to the same host:port share a single TCP connection.
/// HTTP/1.1 connections are also pooled for reuse via keep-alive.
#[derive(Clone)]
pub struct Client {
    connector: BoringConnector,
    h3_client: H3Client,
    alt_svc_cache: Arc<AltSvcCache>,
    /// HTTP/2 connection pool for multiplexing
    h2_pool: Arc<RwLock<HashMap<PoolKey, H2PooledConnection>>>,
    /// HTTP/1.1 connection pool for reuse
    h1_pool: Arc<ConnectionPool>,
    http2_settings: Http2Settings,
    pseudo_order: PseudoHeaderOrder,
    default_version: HttpVersion,
    timeout: Option<Duration>,
    /// Whether to opportunistically try HTTP/3 when Alt-Svc indicates support
    h3_upgrade_enabled: bool,
    /// Force HTTP/2 prior knowledge (H2C) for cleartext connections
    http2_prior_knowledge: bool,
}

/// Builder for HTTP requests.
pub struct RequestBuilder<'a> {
    client: &'a Client,
    uri: String,
    method: Method,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    version: Option<HttpVersion>,
}

/// Builder for creating HTTP clients.
pub struct ClientBuilder {
    fingerprint: FingerprintProfile,
    http2_settings: Option<Http2Settings>,
    pseudo_order: PseudoHeaderOrder,
    timeout: Option<Duration>,
    prefer_http2: bool,
    h3_upgrade_enabled: bool,
    http2_prior_knowledge: bool,
    root_certs: Vec<Vec<u8>>,
}

impl Client {
    /// Create a new client builder.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Create a GET request builder.
    pub fn get(&self, url: impl Into<String>) -> RequestBuilder<'_> {
        RequestBuilder {
            client: self,
            uri: url.into(),
            method: Method::GET,
            headers: Vec::new(),
            body: None,
            version: None,
        }
    }

    /// Create a POST request builder.
    pub fn post(&self, url: impl Into<String>) -> RequestBuilder<'_> {
        RequestBuilder {
            client: self,
            uri: url.into(),
            method: Method::POST,
            headers: Vec::new(),
            body: None,
            version: None,
        }
    }

    /// Create a PUT request builder.
    pub fn put(&self, url: impl Into<String>) -> RequestBuilder<'_> {
        RequestBuilder {
            client: self,
            uri: url.into(),
            method: Method::PUT,
            headers: Vec::new(),
            body: None,
            version: None,
        }
    }

    /// Create a DELETE request builder.
    pub fn delete(&self, url: impl Into<String>) -> RequestBuilder<'_> {
        RequestBuilder {
            client: self,
            uri: url.into(),
            method: Method::DELETE,
            headers: Vec::new(),
            body: None,
            version: None,
        }
    }

    /// Create a custom method request builder.
    pub fn request(&self, method: Method, url: impl Into<String>) -> RequestBuilder<'_> {
        RequestBuilder {
            client: self,
            uri: url.into(),
            method,
            headers: Vec::new(),
            body: None,
            version: None,
        }
    }

    /// Get the Alt-Svc cache for manual inspection or manipulation.
    pub fn alt_svc_cache(&self) -> &Arc<AltSvcCache> {
        &self.alt_svc_cache
    }
}

impl<'a> RequestBuilder<'a> {
    /// Add a header to the request.
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((key.into(), value.into()));
        self
    }

    /// Set all headers (replaces existing headers).
    pub fn headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
        self
    }

    /// Set the request body.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Set the HTTP version preference.
    pub fn version(mut self, version: HttpVersion) -> Self {
        self.version = Some(version);
        self
    }

    /// Send the request and return the response with streaming body.
    /// Returns (Response, Receiver for body chunks).
    /// The response body is empty - chunks arrive via the receiver.
    pub async fn send_streaming(
        self,
    ) -> Result<(
        Response,
        tokio::sync::mpsc::Receiver<std::result::Result<Bytes, crate::transport::h2::H2Error>>,
    )> {
        let version = self.version.unwrap_or(self.client.default_version);

        // Only HTTP/2 supports streaming currently
        if !matches!(version, HttpVersion::Http2 | HttpVersion::Auto) {
            return Err(Error::HttpProtocol(
                "Streaming only supported for HTTP/2".into(),
            ));
        }

        // Parse URI
        let uri: Uri = self
            .uri
            .parse()
            .map_err(|e| Error::HttpProtocol(format!("Invalid URI: {}", e)))?;

        let _pool_key = Self::make_pool_key(&uri);

        // For HTTP/2 streaming, we need direct connection access (no pooling for streaming)
        let stream = self.client.connector.connect(&uri).await?;

        // Ensure ALPN negotiated h2
        let alpn = stream.alpn_protocol();
        if !alpn.is_h2() {
            return Err(Error::HttpProtocol(format!(
                "Expected h2 ALPN, got {:?}",
                alpn
            )));
        }

        // Create H2 connection
        let mut h2_conn = H2Connection::connect(
            stream,
            self.client.http2_settings.clone(),
            self.client.pseudo_order,
        )
        .await?;

        // Build HTTP request
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        let host = uri.host().unwrap_or("localhost");
        let authority = if let Some(port) = uri.port_u16() {
            if port == 443 {
                host.to_string()
            } else {
                format!("{}:{}", host, port)
            }
        } else {
            host.to_string()
        };

        // Build URI with scheme and authority for HTTP/2
        // Note: http::Request::builder() doesn't accept pseudo-headers via .header()
        // The :method, :scheme, :authority, :path pseudo-headers are set implicitly
        // via .method() and .uri() - the URI must include scheme+authority for HTTP/2
        let full_uri = format!("https://{}{}", authority, path);
        let mut request_builder = http::Request::builder()
            .method(self.method.clone())
            .uri(&full_uri);

        // Add custom headers (pseudo-headers are derived from method/uri)
        for (key, value) in &self.headers {
            request_builder = request_builder.header(key.as_str(), value.as_str());
        }

        let body = self.body.map(Bytes::from).unwrap_or_default();
        let request = request_builder
            .body(body)
            .map_err(|e| Error::HttpProtocol(format!("Failed to build request: {}", e)))?;

        // Send streaming request
        let (response, rx) = h2_conn.send_request_streaming(request).await?;

        // Spawn task to read streaming frames
        tokio::spawn(async move {
            loop {
                match h2_conn.read_streaming_frames().await {
                    Ok(true) => continue,
                    Ok(false) => break,
                    Err(e) => {
                        tracing::debug!("Streaming read error: {}", e);
                        break;
                    }
                }
            }
        });

        // Convert http::Response to our Response type
        let status = response.status().as_u16();
        let headers: Vec<String> = response
            .headers()
            .iter()
            .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("")))
            .collect();

        let our_response = crate::response::Response::new(
            status,
            headers,
            Bytes::new(), // Body comes through rx
            "HTTP/2".to_string(),
        );

        Ok((our_response.with_url(self.uri.clone()), rx))
    }

    /// Send the request and return the response.
    pub async fn send(self) -> Result<Response> {
        let version = self.version.unwrap_or(self.client.default_version);

        // HTTP/3 only - go directly to H3
        if matches!(version, HttpVersion::Http3Only) {
            return self.send_h3().await;
        }

        // HTTP/3 preferred - try H3 first, fall back to H1/H2
        if matches!(version, HttpVersion::Http3) {
            match self.send_h3_inner().await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    tracing::debug!("HTTP/3 failed, falling back to HTTP/1.1 or HTTP/2: {}", e);
                    // Fall through to H1/H2
                }
            }
        }

        // Auto mode - check Alt-Svc cache for HTTP/3 upgrade opportunity
        if matches!(version, HttpVersion::Auto) && self.client.h3_upgrade_enabled {
            let origin = self.get_origin();
            if let Some(alt_svc) = self.client.alt_svc_cache.get_h3_alternative(&origin).await {
                tracing::debug!(
                    "Alt-Svc indicates HTTP/3 support for {}, attempting upgrade",
                    origin
                );

                // Try HTTP/3 to the alternative endpoint
                let h3_url = if let Some(ref host) = alt_svc.host {
                    // Different host
                    format!("https://{}:{}{}", host, alt_svc.port, self.get_path())
                } else {
                    // Same host, different port (or same port)
                    self.uri.clone()
                };

                match self
                    .client
                    .h3_client
                    .send_request(
                        &h3_url,
                        self.method.as_str(),
                        self.headers
                            .iter()
                            .map(|(k, v)| (k.as_str(), v.as_str()))
                            .collect(),
                        self.body.clone(),
                    )
                    .await
                {
                    Ok(response) => {
                        let resp: Response = response;
                        return Ok(resp.with_url(h3_url));
                    }
                    Err(e) => {
                        tracing::debug!("HTTP/3 upgrade failed, using HTTP/1.1 or HTTP/2: {}", e);
                        // Fall through to H1/H2
                    }
                }
            }
        }

        // HTTP/1.1 or HTTP/2 via TCP+TLS
        self.send_h1_h2(version).await
    }

    /// Send via HTTP/3 only (no fallback).
    async fn send_h3(self) -> Result<Response> {
        self.send_h3_inner().await
    }

    /// Internal HTTP/3 send.
    async fn send_h3_inner(&self) -> Result<Response> {
        let fut = self.client.h3_client.send_request(
            &self.uri,
            self.method.as_str(),
            self.headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
            self.body.clone(),
        );

        let response = if let Some(timeout_duration) = self.client.timeout {
            tokio_timeout(timeout_duration, fut)
                .await
                .map_err(|_| Error::Timeout("HTTP/3 request timed out".into()))??
        } else {
            fut.await?
        };

        // Set effective_url so redirect engines can track the current URL
        Ok(response.with_url(self.uri.clone()))
    }

    /// Send via HTTP/1.1 or HTTP/2.
    ///
    /// HTTP/2 connections are pooled and multiplexed - subsequent requests to the
    /// same host:port reuse the existing connection instead of creating a new one.
    async fn send_h1_h2(self, version: HttpVersion) -> Result<Response> {
        // Save the original URL for effective_url tracking
        let request_url = self.uri.clone();

        // Parse URI
        let uri: Uri = self
            .uri
            .parse()
            .map_err(|e| Error::HttpProtocol(format!("Invalid URI: {}", e)))?;

        // Determine if we should use HTTP/2
        let prefer_http2 = match version {
            HttpVersion::Http1_1 => false,
            HttpVersion::Http2 => true,
            HttpVersion::Http3 | HttpVersion::Http3Only => {
                return Err(Error::HttpProtocol("HTTP/3 should use send_h3".into()));
            }
            HttpVersion::Auto => matches!(self.client.default_version, HttpVersion::Http2),
        };

        // Extract values needed after potential moves
        let h3_upgrade_enabled = self.client.h3_upgrade_enabled;
        let alt_svc_cache = self.client.alt_svc_cache.clone();
        let origin = self.get_origin();

        // For HTTP/2, try to use pooled connection first
        if prefer_http2 {
            let pool_key = Self::make_pool_key(&uri);

            // Check for existing pooled connection
            let pooled = {
                let pool = self.client.h2_pool.read().await;
                pool.get(&pool_key).cloned()
            };

            if let Some(conn) = pooled {
                // Try to use pooled connection
                let result = conn
                    .send_request(
                        self.method.clone(),
                        &uri,
                        self.headers.clone(),
                        self.body.clone().map(Bytes::from),
                    )
                    .await;

                match result {
                    Ok(response) => {
                        // Parse Alt-Svc header for HTTP/3 discovery
                        if h3_upgrade_enabled {
                            if let Some(alt_svc) = response.get_header("alt-svc") {
                                alt_svc_cache.parse_and_store(&origin, alt_svc).await;
                            }
                        }
                        return Ok(response.with_url(request_url));
                    }
                    Err(e) => {
                        // Connection failed - remove from pool and create new one
                        tracing::debug!("Pooled HTTP/2 connection failed, creating new: {}", e);
                        let mut pool = self.client.h2_pool.write().await;
                        pool.remove(&pool_key);
                    }
                }
            }

            // No pooled connection or it failed - create new one
            let stream = self.client.connector.connect(&uri).await?;

            // Verify ALPN negotiated h2
            let use_http2 = if self.client.http2_prior_knowledge && !stream.alpn_protocol().is_h2()
            {
                // For Prior Knowledge, we use H2 if strictly requested, even if no ALPN (e.g. cleartext)
                true
            } else if let MaybeHttpsStream::Https(ref ssl_stream) = stream {
                ssl_stream.ssl().selected_alpn_protocol() == Some(b"h2")
            } else {
                false
            };

            if use_http2 {
                // Create HTTP/2 connection and pool it
                let h2_conn = H2Connection::connect(
                    stream,
                    self.client.http2_settings.clone(),
                    self.client.pseudo_order,
                )
                .await?;
                let pooled_conn = H2PooledConnection::new(h2_conn);

                // Store in pool
                {
                    let mut pool = self.client.h2_pool.write().await;
                    pool.insert(pool_key, pooled_conn.clone());
                }

                // Send request
                let fut = pooled_conn.send_request(
                    self.method,
                    &uri,
                    self.headers,
                    self.body.map(Bytes::from),
                );

                let response = if let Some(timeout_duration) = self.client.timeout {
                    tokio_timeout(timeout_duration, fut)
                        .await
                        .map_err(|_| Error::Timeout("Request timed out".into()))?
                } else {
                    fut.await
                }?;

                // Parse Alt-Svc header for HTTP/3 discovery
                if h3_upgrade_enabled {
                    if let Some(alt_svc) = response.get_header("alt-svc") {
                        alt_svc_cache.parse_and_store(&origin, alt_svc).await;
                    }
                }

                return Ok(response.with_url(request_url));
            }
            // Fall through to HTTP/1.1 if h2 not negotiated
        }

        // HTTP/1.1 path (with connection pooling)
        let stream = self.client.connector.connect(&uri).await?;

        // Check if server negotiated HTTP/2 via ALPN - if so, we must use HTTP/2
        // even though we preferred HTTP/1.1 (server choice takes precedence)
        let server_wants_h2 = if let MaybeHttpsStream::Https(ref ssl_stream) = stream {
            ssl_stream.ssl().selected_alpn_protocol() == Some(b"h2")
        } else {
            false
        };

        let response = if server_wants_h2 {
            // Server negotiated HTTP/2 - we must speak HTTP/2 or they'll close connection
            tracing::debug!("Server selected h2 via ALPN, upgrading to HTTP/2");

            let h2_conn = H2Connection::connect(
                stream,
                self.client.http2_settings.clone(),
                self.client.pseudo_order,
            )
            .await?;
            let pooled_conn = H2PooledConnection::new(h2_conn);

            // Store in pool for reuse
            let pool_key = Self::make_pool_key(&uri);
            {
                let mut pool = self.client.h2_pool.write().await;
                pool.insert(pool_key, pooled_conn.clone());
            }

            let fut = pooled_conn.send_request(
                self.method,
                &uri,
                self.headers,
                self.body.map(Bytes::from),
            );

            if let Some(timeout_duration) = self.client.timeout {
                tokio_timeout(timeout_duration, fut)
                    .await
                    .map_err(|_| Error::Timeout("Request timed out".into()))?
            } else {
                fut.await
            }?
        } else {
            // HTTP/1.1 as expected - use connection pooling
            let pool_key = Self::make_pool_key(&uri);

            // Try to get a pooled connection
            let mut stream_opt = self.client.h1_pool.get_h1(&pool_key).await;
            let mut used_pooled = stream_opt.is_some();

            // If no pooled connection, create a new one
            let mut stream = if let Some(stream) = stream_opt.take() {
                tracing::debug!("H1: Reusing pooled connection for {:?}", pool_key);
                stream
            } else {
                tracing::debug!("H1: Creating new connection for {:?}", pool_key);
                self.client.connector.connect(&uri).await?
            };

            // Send request - retry with new connection if pooled connection fails
            let result = loop {
                let stream_for_request = stream;
                let fut = Self::do_send_http1(
                    stream_for_request,
                    self.method.clone(),
                    &uri,
                    self.headers.clone(),
                    self.body.clone().map(Bytes::from),
                );

                let request_result = if let Some(timeout_duration) = self.client.timeout {
                    tokio_timeout(timeout_duration, fut)
                        .await
                        .map_err(|_| Error::Timeout("Request timed out".into()))?
                } else {
                    fut.await
                };

                match request_result {
                    Ok((resp, returned_stream)) => {
                        // Success - return stream to pool for reuse
                        self.client
                            .h1_pool
                            .put_h1(pool_key.clone(), returned_stream)
                            .await;
                        break Ok(resp);
                    }
                    Err(e) => {
                        // Check if this was a pooled connection that failed
                        if used_pooled {
                            tracing::debug!(
                                "H1: Pooled connection failed for {:?}, creating new: {}",
                                pool_key,
                                e
                            );
                            // Try again with a fresh connection
                            stream = self.client.connector.connect(&uri).await?;
                            used_pooled = false; // Mark that we're no longer using a pooled connection
                            continue;
                        } else {
                            // Fresh connection also failed - return error
                            tracing::debug!(
                                "H1: Request failed for {:?}, discarding connection: {}",
                                pool_key,
                                e
                            );
                            break Err(e);
                        }
                    }
                }
            };

            result?
        };

        // Parse Alt-Svc header for HTTP/3 discovery
        if h3_upgrade_enabled {
            if let Some(alt_svc) = response.get_header("alt-svc") {
                alt_svc_cache.parse_and_store(&origin, alt_svc).await;
            }
        }

        Ok(response.with_url(request_url))
    }

    /// Create a pool key from a URI.
    fn make_pool_key(uri: &Uri) -> PoolKey {
        let host = uri.host().unwrap_or("localhost").to_string();
        let is_https = uri.scheme_str() == Some("https");
        let port = uri.port_u16().unwrap_or(if is_https { 443 } else { 80 });
        PoolKey::new(host, port, is_https)
    }

    async fn do_send_http1(
        stream: MaybeHttpsStream,
        method: Method,
        uri: &Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<(Response, MaybeHttpsStream)> {
        let mut conn = H1Connection::new(stream);
        let response = conn.send_request(method, uri, headers, body).await?;
        let stream = conn.into_inner();
        Ok((response, stream))
    }

    /// Extract origin (scheme://host:port) from URI.
    fn get_origin(&self) -> String {
        if let Ok(uri) = self.uri.parse::<Uri>() {
            let scheme = uri.scheme_str().unwrap_or("https");
            let host = uri.host().unwrap_or("localhost");
            let port = uri
                .port_u16()
                .unwrap_or(if scheme == "https" { 443 } else { 80 });

            if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
                format!("{}://{}", scheme, host)
            } else {
                format!("{}://{}:{}", scheme, host, port)
            }
        } else {
            self.uri.clone()
        }
    }

    /// Extract path from URI.
    fn get_path(&self) -> String {
        if let Ok(uri) = self.uri.parse::<Uri>() {
            uri.path_and_query()
                .map(|pq| pq.as_str().to_string())
                .unwrap_or_else(|| "/".to_string())
        } else {
            "/".to_string()
        }
    }
}

impl ClientBuilder {
    /// Create a new client builder with default settings.
    pub fn new() -> Self {
        Self {
            fingerprint: FingerprintProfile::default(),
            http2_settings: None,
            pseudo_order: PseudoHeaderOrder::Chrome,
            timeout: None,
            prefer_http2: true, // HTTP/2 preferred by default (falls back to HTTP/1.1 if not supported)

            h3_upgrade_enabled: true, // Enable by default
            http2_prior_knowledge: false,
            root_certs: Vec::new(),
        }
    }

    /// Set the fingerprint profile.
    pub fn fingerprint(mut self, fingerprint: FingerprintProfile) -> Self {
        self.fingerprint = fingerprint;
        self
    }

    /// Set HTTP/2 settings for fingerprinting.
    pub fn http2_settings(mut self, settings: Http2Settings) -> Self {
        self.http2_settings = Some(settings);
        self
    }

    /// Set pseudo-header ordering for HTTP/2 fingerprinting.
    pub fn pseudo_order(mut self, order: PseudoHeaderOrder) -> Self {
        self.pseudo_order = order;
        self
    }

    /// Set request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set HTTP/2 preference (for Auto version selection).
    pub fn prefer_http2(mut self, prefer: bool) -> Self {
        self.prefer_http2 = prefer;
        self
    }

    /// Enable or disable automatic HTTP/3 upgrade via Alt-Svc headers.
    ///
    /// When enabled (default), the client will:
    /// 1. Parse Alt-Svc headers from HTTP/1.1 and HTTP/2 responses
    /// 2. Cache HTTP/3 endpoints discovered via Alt-Svc
    /// 3. Attempt HTTP/3 for subsequent requests when cached
    pub fn h3_upgrade(mut self, enabled: bool) -> Self {
        self.h3_upgrade_enabled = enabled;
        self
    }

    /// Enable HTTP/2 Prior Knowledge (H2C) for cleartext connections.
    /// When enabled, connecting to `http://` URIs will assume HTTP/2.
    pub fn http2_prior_knowledge(mut self, enabled: bool) -> Self {
        self.http2_prior_knowledge = enabled;
        // Prior knowledge implies preferring H2
        if enabled {
            self.prefer_http2 = true;
        }
        self
    }

    /// Add a custom root certificate (DER or PEM) to the trust store.
    pub fn add_root_certificate(mut self, cert: Vec<u8>) -> Self {
        self.root_certs.push(cert);
        self
    }

    /// Build the client.
    pub fn build(self) -> Result<Client> {
        // Create connector with TLS fingerprint
        let tls_fingerprint = self.fingerprint.tls_fingerprint();
        let connector = BoringConnector::with_fingerprint(tls_fingerprint.clone())
            .with_root_certificates(self.root_certs);

        // Create H3 client with same TLS fingerprint
        let h3_client = H3Client::with_fingerprint(tls_fingerprint);

        // Use provided HTTP/2 settings or default from fingerprint
        let http2_settings = self.http2_settings.unwrap_or_default();

        // Determine default version
        let default_version = if self.prefer_http2 {
            HttpVersion::Http2
        } else {
            HttpVersion::Http1_1
        };

        Ok(Client {
            connector,
            h3_client,
            alt_svc_cache: Arc::new(AltSvcCache::new()),
            h2_pool: Arc::new(RwLock::new(HashMap::new())),
            h1_pool: Arc::new(ConnectionPool::new()),
            http2_settings,
            pseudo_order: self.pseudo_order,
            default_version,
            timeout: self.timeout,

            h3_upgrade_enabled: self.h3_upgrade_enabled,
            http2_prior_knowledge: self.http2_prior_knowledge,
        })
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for AltSvcCache {
    fn default() -> Self {
        Self::new()
    }
}
