//! BoringSSL TLS connector for hyper.

use boring::ssl::{SslConnector, SslMethod, SslVersion};
use tokio_boring::SslStream;
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use hyper::Uri;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::Service;
use std::io;

use crate::fingerprint::tls::TlsFingerprint;
use crate::error::Error;

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
}

impl BoringConnector {
    /// Create a new connector with default TLS configuration.
    pub fn new() -> Self {
        Self { tls_config: None }
    }
    
    /// Create a connector with TLS fingerprint configuration.
    pub fn with_fingerprint(fp: TlsFingerprint) -> Self {
        Self { tls_config: Some(fp) }
    }
    
    fn configure_ssl(&self, _domain: &str) -> Result<SslConnector, Error> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())
            .map_err(|e| Error::Tls(format!("Failed to create SSL connector: {}", e)))?;
        
        if let Some(fp) = &self.tls_config {
            // Set cipher list from fingerprint
            if !fp.cipher_list.is_empty() {
                let cipher_str = fp.cipher_list.join(":");
                builder.set_cipher_list(&cipher_str)
                    .map_err(|e| Error::Tls(format!("Failed to set cipher list: {}", e)))?;
            }
            
            // Set curves/groups from fingerprint
            if !fp.curves.is_empty() {
                let curves_str = fp.curves.join(":");
                builder.set_curves_list(&curves_str)
                    .map_err(|e| Error::Tls(format!("Failed to set curves: {}", e)))?;
            }
            
            // Set signature algorithms from fingerprint
            if !fp.sigalgs.is_empty() {
                let sigalgs_str = fp.sigalgs.join(":");
                builder.set_sigalgs_list(&sigalgs_str)
                    .map_err(|e| Error::Tls(format!("Failed to set signature algorithms: {}", e)))?;
            }
            
            // Enable GREASE and extension permutation for Chrome-like behavior
            if fp.grease {
                unsafe {
                    let ctx = builder.as_ptr() as *mut SSL_CTX;
                    SSL_CTX_set_grease_enabled(ctx, 1);
                    SSL_CTX_set_permute_extensions(ctx, 1);
                }
            }
            
            // Set min/max TLS version
            builder.set_min_proto_version(Some(SslVersion::TLS1_2))
                .map_err(|e| Error::Tls(format!("Failed to set min TLS version: {}", e)))?;
            builder.set_max_proto_version(Some(SslVersion::TLS1_3))
                .map_err(|e| Error::Tls(format!("Failed to set max TLS version: {}", e)))?;
        } else {
            // Default configuration
            builder.set_min_proto_version(Some(SslVersion::TLS1_2))
                .map_err(|e| Error::Tls(format!("Failed to set min TLS version: {}", e)))?;
            builder.set_max_proto_version(Some(SslVersion::TLS1_3))
                .map_err(|e| Error::Tls(format!("Failed to set max TLS version: {}", e)))?;
        }
        
        // Enable ALPN for HTTP/2
        builder.set_alpn_protos(b"\x02h2\x08http/1.1")
            .map_err(|e| Error::Tls(format!("Failed to set ALPN: {}", e)))?;
        
        Ok(builder.build())
    }
}

/// Stream that can be either HTTP (plain TCP) or HTTPS (TLS).
pub enum MaybeHttpsStream {
    /// Plain TCP stream for HTTP.
    Http(TcpStream),
    /// TLS-wrapped stream for HTTPS.
    Https(SslStream<TcpStream>),
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

impl Service<Uri> for BoringConnector {
    type Response = MaybeHttpsStream;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let tls_config = self.tls_config.clone();
        
        Box::pin(async move {
            let host = uri.host().ok_or_else(|| Error::Connection("Missing host".into()))?;
            let port = uri.port_u16().unwrap_or(
                if uri.scheme_str() == Some("https") { 443 } else { 80 }
            );
            
            let addr = format!("{}:{}", host, port);
            let tcp_stream = TcpStream::connect(&addr).await
                .map_err(|e| Error::Connection(format!("Failed to connect to {}: {}", addr, e)))?;
            
            if uri.scheme_str() == Some("https") {
                let connector = Self { tls_config };
                let ssl_connector = connector.configure_ssl(host)?;
                
                let ssl_config = ssl_connector.configure()
                    .map_err(|e| Error::Tls(format!("Failed to configure SSL: {}", e)))?;
                
                let ssl_stream = tokio_boring::connect(ssl_config, host, tcp_stream).await
                    .map_err(|e| Error::Tls(format!("TLS handshake failed: {}", e)))?;
                
                Ok(MaybeHttpsStream::Https(ssl_stream))
            } else {
                Ok(MaybeHttpsStream::Http(tcp_stream))
            }
        })
    }
}

impl Default for BoringConnector {
    fn default() -> Self {
        Self::new()
    }
}
