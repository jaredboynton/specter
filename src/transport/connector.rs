//! BoringSSL TLS connector.

use boring::ssl::{SslConnector, SslMethod, SslSessionCacheMode, SslVersion};
use http::Uri;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_boring::SslStream;

use crate::error::Error;
use crate::fingerprint::tls::TlsFingerprint;
use crate::transport::tcp::{configure_tcp_socket, TcpFingerprint};

// FFI bindings for BoringSSL extension control
use boring_sys::SSL_CTX;
use std::os::raw::c_int;

extern "C" {
    /// Enable GREASE (Generate Random Extensions And Sustain Extensibility)
    pub fn SSL_CTX_set_grease_enabled(ctx: *mut SSL_CTX, enabled: c_int) -> c_int;
    /// Enable extension order permutation (Chrome 110+ behavior)
    pub fn SSL_CTX_set_permute_extensions(ctx: *mut SSL_CTX, enabled: c_int) -> c_int;
}

/// BoringSSL-based TLS connector for hyper.
#[derive(Clone)]
pub struct BoringConnector {
    tls_config: Option<TlsFingerprint>,
    tcp_fingerprint: Option<TcpFingerprint>,
}

impl BoringConnector {
    /// Create a new connector with default TLS configuration.
    pub fn new() -> Self {
        Self {
            tls_config: None,
            tcp_fingerprint: None,
        }
    }

    /// Create a connector with TLS fingerprint configuration.
    pub fn with_fingerprint(fp: TlsFingerprint) -> Self {
        Self {
            tls_config: Some(fp),
            tcp_fingerprint: None,
        }
    }

    /// Create a connector with both TLS and TCP fingerprint configuration.
    pub fn with_fingerprints(tls_fp: TlsFingerprint, tcp_fp: TcpFingerprint) -> Self {
        Self {
            tls_config: Some(tls_fp),
            tcp_fingerprint: Some(tcp_fp),
        }
    }

    /// Set TCP fingerprint configuration.
    pub fn with_tcp_fingerprint(mut self, tcp_fp: TcpFingerprint) -> Self {
        self.tcp_fingerprint = Some(tcp_fp);
        self
    }

    fn configure_ssl(&self, _domain: &str) -> Result<SslConnector, Error> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())
            .map_err(|e| Error::Tls(format!("Failed to create SSL connector: {}", e)))?;

        if let Some(fp) = &self.tls_config {
            // Set cipher list from fingerprint
            if !fp.cipher_list.is_empty() {
                let cipher_str = fp.cipher_list.join(":");
                builder
                    .set_cipher_list(&cipher_str)
                    .map_err(|e| Error::Tls(format!("Failed to set cipher list: {}", e)))?;
            }

            // Set curves/groups from fingerprint
            if !fp.curves.is_empty() {
                let curves_str = fp.curves.join(":");
                builder
                    .set_curves_list(&curves_str)
                    .map_err(|e| Error::Tls(format!("Failed to set curves: {}", e)))?;
            }

            // Set signature algorithms from fingerprint
            if !fp.sigalgs.is_empty() {
                let sigalgs_str = fp.sigalgs.join(":");
                builder.set_sigalgs_list(&sigalgs_str).map_err(|e| {
                    Error::Tls(format!("Failed to set signature algorithms: {}", e))
                })?;
            }

            // Enable GREASE and extension permutation for Chrome-like behavior
            // Firefox also randomizes extensions but doesn't use GREASE
            unsafe {
                let ctx = builder.as_ptr() as *mut SSL_CTX;
                if fp.grease {
                    // Chrome: enable GREASE and extension permutation
                    SSL_CTX_set_grease_enabled(ctx, 1);
                    SSL_CTX_set_permute_extensions(ctx, 1);
                } else {
                    // Firefox: enable extension permutation but NOT GREASE
                    SSL_CTX_set_grease_enabled(ctx, 0);
                    SSL_CTX_set_permute_extensions(ctx, 1);
                }
            }
            
            // Note: extension_order field in TlsFingerprint is for reference only.
            // Modern browsers (Chrome 110+, Firefox 135+) randomize extension order,
            // so we cannot set a static order. The extension_order field is used for
            // JA3 fingerprint reference (though JA3 will vary due to randomization)
            // and JA4 fingerprinting (which sorts extensions alphabetically).

            // Set min/max TLS version
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_2))
                .map_err(|e| Error::Tls(format!("Failed to set min TLS version: {}", e)))?;
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .map_err(|e| Error::Tls(format!("Failed to set max TLS version: {}", e)))?;
        } else {
            // Default configuration
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_2))
                .map_err(|e| Error::Tls(format!("Failed to set min TLS version: {}", e)))?;
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .map_err(|e| Error::Tls(format!("Failed to set max TLS version: {}", e)))?;
        }

        // Enable session caching (browsers use this for session resumption)
        // This enables TLS session tickets and session ID caching
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);

        // Enable ALPN for HTTP/2
        builder
            .set_alpn_protos(b"\x02h2\x08http/1.1")
            .map_err(|e| Error::Tls(format!("Failed to set ALPN: {}", e)))?;

        Ok(builder.build())
    }
}

/// Negotiated ALPN protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpnProtocol {
    /// HTTP/2 ("h2")
    H2,
    /// HTTP/1.1 ("http/1.1")
    Http1,
    /// No ALPN negotiated or unknown protocol
    Unknown,
}

impl AlpnProtocol {
    /// Check if HTTP/2 was negotiated.
    pub fn is_h2(&self) -> bool {
        matches!(self, Self::H2)
    }

    /// Check if HTTP/1.1 was negotiated.
    pub fn is_http1(&self) -> bool {
        matches!(self, Self::Http1)
    }
}

/// Stream that can be either HTTP (plain TCP) or HTTPS (TLS).
pub enum MaybeHttpsStream {
    /// Plain TCP stream for HTTP.
    Http(TcpStream),
    /// TLS-wrapped stream for HTTPS.
    Https(SslStream<TcpStream>),
}

impl MaybeHttpsStream {
    /// Get the negotiated ALPN protocol.
    ///
    /// For HTTPS connections, returns the protocol negotiated during TLS handshake.
    /// For plain HTTP connections, returns `Unknown` (no TLS = no ALPN).
    ///
    /// **IMPORTANT**: Always check ALPN before using HTTP/2. If the server negotiated
    /// HTTP/1.1 (or no ALPN), attempting HTTP/2 will fail immediately.
    pub fn alpn_protocol(&self) -> AlpnProtocol {
        match self {
            MaybeHttpsStream::Http(_) => AlpnProtocol::Unknown,
            MaybeHttpsStream::Https(stream) => match stream.ssl().selected_alpn_protocol() {
                Some(b"h2") => AlpnProtocol::H2,
                Some(b"http/1.1") => AlpnProtocol::Http1,
                _ => AlpnProtocol::Unknown,
            },
        }
    }

    /// Check if HTTP/2 was negotiated via ALPN.
    ///
    /// Convenience method for `self.alpn_protocol().is_h2()`.
    pub fn is_h2(&self) -> bool {
        self.alpn_protocol().is_h2()
    }
}

impl AsyncRead for MaybeHttpsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(stream) => Pin::new(stream).poll_read(cx, buf),
            MaybeHttpsStream::Https(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeHttpsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            MaybeHttpsStream::Http(stream) => Pin::new(stream).poll_write(cx, buf),
            MaybeHttpsStream::Https(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(stream) => Pin::new(stream).poll_flush(cx),
            MaybeHttpsStream::Https(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(stream) => Pin::new(stream).poll_shutdown(cx),
            MaybeHttpsStream::Https(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl BoringConnector {
    /// Connect to a URI, returning either a plain TCP or TLS stream.
    pub async fn connect(&self, uri: &Uri) -> Result<MaybeHttpsStream, Error> {
        let host = uri
            .host()
            .ok_or_else(|| Error::Connection("Missing host".into()))?;
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            });

        let addr = format!("{}:{}", host, port);
        
        // Configure TCP socket options if fingerprint is provided
        let tcp_stream = if let Some(ref tcp_fp) = self.tcp_fingerprint {
            // Create socket2 socket, configure it, then connect and convert to tokio TcpStream
            use socket2::{Domain, Socket, Type};
            use std::net::SocketAddr;
            use tokio::task;
            use tokio::net::lookup_host;
            
            // Resolve hostname to IP address (tokio handles async DNS resolution)
            let socket_addr: SocketAddr = lookup_host(&addr)
                .await
                .map_err(|e| Error::Connection(format!("DNS resolution failed for {}: {}", addr, e)))?
                .next()
                .ok_or_else(|| Error::Connection(format!("No addresses found for {}", addr)))?;
            
            let domain = match socket_addr {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };
            
            // Perform blocking socket operations in a blocking task
            let tcp_fp_clone = tcp_fp.clone();
            let socket_addr_copy = socket_addr;
            let std_stream = task::spawn_blocking(move || -> Result<std::net::TcpStream, Error> {
                let socket = Socket::new(domain, Type::STREAM, Some(socket2::Protocol::TCP))
                    .map_err(|e| Error::Connection(format!("Failed to create socket: {}", e)))?;
                
                // Configure TCP fingerprint options
                configure_tcp_socket(&socket, &tcp_fp_clone)
                    .map_err(|e| Error::Connection(format!("Failed to configure TCP socket: {}", e)))?;
                
                // Connect synchronously (socket2 handles this)
                socket.connect(&socket_addr_copy.into())
                    .map_err(|e| Error::Connection(format!("Failed to connect: {}", e)))?;
                
                // Set to non-blocking mode for tokio compatibility (required by tokio 1.48+)
                socket.set_nonblocking(true)
                    .map_err(|e| Error::Connection(format!("Failed to set non-blocking: {}", e)))?;
                
                // Convert to std::net::TcpStream
                Ok(socket.into())
            })
            .await
            .map_err(|e| Error::Connection(format!("Blocking task failed: {}", e)))??;
            
            // Convert to tokio TcpStream (socket is already non-blocking)
            TcpStream::from_std(std_stream)
                .map_err(|e| Error::Connection(format!("Failed to convert to tokio stream: {}", e)))?
        } else {
            // Default connection without TCP fingerprinting
            TcpStream::connect(&addr)
                .await
                .map_err(|e| Error::Connection(format!("Failed to connect to {}: {}", addr, e)))?
        };

        if uri.scheme_str() == Some("https") {
            let ssl_connector = self.configure_ssl(host)?;

            let ssl_config = ssl_connector
                .configure()
                .map_err(|e| Error::Tls(format!("Failed to configure SSL: {}", e)))?;

            let ssl_stream = tokio_boring::connect(ssl_config, host, tcp_stream)
                .await
                .map_err(|e| Error::Tls(format!("TLS handshake failed: {}", e)))?;

            Ok(MaybeHttpsStream::Https(ssl_stream))
        } else {
            Ok(MaybeHttpsStream::Http(tcp_stream))
        }
    }
}

impl Default for BoringConnector {
    fn default() -> Self {
        Self::new()
    }
}
