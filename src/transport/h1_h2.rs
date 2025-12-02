//! HTTP/1.1 and HTTP/2 transport via hyper.

use hyper::client::conn::http1;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use http_body_util::{BodyExt, Full};
use bytes::Bytes;
use hyper::{Method, Request as HyperRequest, body::Incoming, Uri as HyperUri};
use std::time::Duration;
use std::future::Future;
use std::pin::Pin;
use tokio::time::timeout as tokio_timeout;
use tower::Service;

use crate::fingerprint::{FingerprintProfile, http2::Http2Settings};
use crate::transport::connector::{BoringConnector, MaybeHttpsStream};
use crate::response::Response;
use crate::error::{Error, Result};
use crate::version::HttpVersion;

/// HTTP/1.1 and HTTP/2 client with fingerprinting support.
pub struct Client {
    connector: BoringConnector,
    fingerprint: FingerprintProfile,
    http2_settings: Http2Settings,
    default_version: HttpVersion,
    timeout: Option<Duration>,
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
    timeout: Option<Duration>,
    prefer_http2: bool,
}

impl Client {
    /// Create a new client builder.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Create a GET request builder.
    pub fn get(&self, url: impl Into<String>) -> RequestBuilder {
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
    pub fn post(&self, url: impl Into<String>) -> RequestBuilder {
        RequestBuilder {
            client: self,
            uri: url.into(),
            method: Method::POST,
            headers: Vec::new(),
            body: None,
            version: None,
        }
    }

    /// Create a custom method request builder.
    pub fn request(&self, method: Method, url: impl Into<String>) -> RequestBuilder {
        RequestBuilder {
            client: self,
            uri: url.into(),
            method,
            headers: Vec::new(),
            body: None,
            version: None,
        }
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

    /// Send the request and return the response.
    pub async fn send(self) -> Result<Response> {
        // Parse URI
        let uri: HyperUri = self.uri.parse()
            .map_err(|e| Error::HttpProtocol(format!("Invalid URI: {}", e)))?;

        // Get connection from connector
        let mut connector = self.client.connector.clone();
        let stream = connector.call(uri.clone()).await?;

        // Determine HTTP version
        let use_http2 = match self.version.unwrap_or(self.client.default_version) {
            HttpVersion::Http1_1 => false,
            HttpVersion::Http2 => true,
            HttpVersion::Http3 | HttpVersion::Http3Only => {
                return Err(Error::HttpProtocol("HTTP/3 not supported in h1_h2 transport".into()));
            }
            HttpVersion::Auto => {
                // Check ALPN if HTTPS
                if let MaybeHttpsStream::Https(ref ssl_stream) = stream {
                    // Check ALPN negotiated protocol
                    if let Some(alpn) = ssl_stream.ssl().selected_alpn_protocol() {
                        alpn == b"h2"
                    } else {
                        // Default to HTTP/2 preference if ALPN not available
                        matches!(self.client.default_version, HttpVersion::Http2)
                    }
                } else {
                    false // HTTP/2 requires TLS
                }
            }
        };

        // Build hyper request
        let mut request_builder = HyperRequest::builder()
            .method(self.method.clone())
            .uri(&uri);

        // Add headers
        let header_map = request_builder.headers_mut()
            .ok_or_else(|| Error::HttpProtocol("Failed to get headers mut".into()))?;
        
        for (key, value) in &self.headers {
            header_map.insert(
                hyper::header::HeaderName::from_bytes(key.as_bytes())
                    .map_err(|e| Error::HttpProtocol(format!("Invalid header name: {}", e)))?,
                hyper::header::HeaderValue::from_str(value)
                    .map_err(|e| Error::HttpProtocol(format!("Invalid header value: {}", e)))?,
            );
        }

        // Set body
        let body = if let Some(body_bytes) = self.body {
            Full::new(Bytes::from(body_bytes))
        } else {
            Full::new(Bytes::new())
        };

        let request = request_builder.body(body)
            .map_err(|e| Error::HttpProtocol(format!("Failed to build request: {}", e)))?;

        // Execute request with timeout if configured
        let response_future: Pin<Box<dyn Future<Output = Result<hyper::Response<Incoming>>> + Send>> = if use_http2 {
            Box::pin(Self::send_http2(stream, request, &self.client.http2_settings))
        } else {
            Box::pin(Self::send_http1(stream, request))
        };

        let response = if let Some(timeout_duration) = self.client.timeout {
            tokio_timeout(timeout_duration, response_future)
                .await
                .map_err(|_| Error::Timeout("Request timed out".into()))?
        } else {
            response_future.await
        }?;

        // Convert hyper response to our Response type
        let (parts, body) = response.into_parts();
        
        // Collect body bytes
        let body_bytes = body.collect().await
            .map_err(|e| Error::HttpProtocol(format!("Failed to read body: {}", e)))?
            .to_bytes();

        // Convert headers to Vec<String>
        let headers: Vec<String> = parts.headers.iter()
            .map(|(name, value)| {
                format!("{}: {}", name, value.to_str().unwrap_or(""))
            })
            .collect();

        // Determine HTTP version string
        let http_version = if use_http2 {
            "HTTP/2"
        } else {
            "HTTP/1.1"
        };

        Ok(Response::new(
            parts.status.as_u16(),
            headers,
            body_bytes,
            http_version.to_string(),
        ))
    }

    async fn send_http1(
        stream: MaybeHttpsStream,
        request: HyperRequest<Full<Bytes>>,
    ) -> Result<hyper::Response<Incoming>> {
        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io).await
            .map_err(|e| Error::HttpProtocol(format!("HTTP/1.1 handshake failed: {}", e)))?;

        // Spawn connection task
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::error!("HTTP/1.1 connection error: {}", e);
            }
        });

        sender.send_request(request).await
            .map_err(|e| Error::HttpProtocol(format!("HTTP/1.1 request failed: {}", e)))
    }

    async fn send_http2(
        stream: MaybeHttpsStream,
        request: HyperRequest<Full<Bytes>>,
        _settings: &Http2Settings, // Keep param for future use but don't apply settings
    ) -> Result<hyper::Response<Incoming>> {
        // Note: HTTP/2 SETTINGS fingerprinting requires lower-level h2 access
        // which hyper doesn't expose. For now use default settings.
        let builder = http2::Builder::new(TokioExecutor::new());
        let io = TokioIo::new(stream);

        let (mut sender, conn) = builder.handshake(io).await
            .map_err(|e| Error::HttpProtocol(format!("HTTP/2 handshake failed: {}", e)))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::error!("HTTP/2 connection error: {}", e);
            }
        });

        sender.send_request(request).await
            .map_err(|e| Error::HttpProtocol(format!("HTTP/2 request failed: {}", e)))
    }
}

impl ClientBuilder {
    /// Create a new client builder with default settings.
    pub fn new() -> Self {
        Self {
            fingerprint: FingerprintProfile::default(),
            http2_settings: None,
            timeout: None,
            prefer_http2: false,
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

    /// Build the client.
    pub fn build(self) -> Result<Client> {
        // Create connector with TLS fingerprint
        let tls_fingerprint = self.fingerprint.tls_fingerprint();
        let connector = BoringConnector::with_fingerprint(tls_fingerprint);

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
            fingerprint: self.fingerprint,
            http2_settings,
            default_version,
            timeout: self.timeout,
        })
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}
