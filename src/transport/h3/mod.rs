//! HTTP/3 Transport Module

mod connection;
mod driver;
mod handle;

pub use connection::H3Connection;
pub use driver::DriverCommand;
pub use handle::H3Handle;

// Re-implement H3Client using the new H3Connection/Handle architecture
// to maintain API compatibility but gain multiplexing.
//
// NOTE: Ideally we'd remove H3Client wrapper completely or just let it manage a pool.
// For now, let's keep H3Client as a factory/pool manager.

use crate::error::{Error, Result};
use crate::fingerprint::tls::TlsFingerprint;
use crate::response::Response;

#[derive(Debug, Clone)]
pub struct H3Client {
    tls_fingerprint: Option<TlsFingerprint>,
    // In future: connection pool
}

impl Default for H3Client {
    fn default() -> Self {
        Self::new()
    }
}

impl H3Client {
    pub fn new() -> Self {
        Self {
            tls_fingerprint: None,
        }
    }

    pub fn with_fingerprint(fp: TlsFingerprint) -> Self {
        Self {
            tls_fingerprint: Some(fp),
        }
    }

    /// Send a request.
    /// Warning: Currently establishes a NEW connection every time (simple wrapper).
    /// To use multiplexing, use `connect()` to get a handle, then reuse handle.
    /// This method is for convenience/backwards compat.
    pub async fn send_request(
        &self,
        url: &str,
        method: &str,
        headers: Vec<(&str, &str)>,
        body: Option<Vec<u8>>,
    ) -> Result<Response> {
        let (_host, _port, _path) = parse_url_host(url)?;

        // This is inefficient (new connection per request) but compatible.
        // Implementing full pooling inside H3Client is Phase 2.

        let config = self.create_quic_config()?;
        let handle = H3Connection::connect(url, config).await?;

        // Convert headers
        let headers_string: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        // Convert body
        let body_bytes = body.map(bytes::Bytes::from);

        let uri: http::Uri = url
            .parse()
            .map_err(|e| Error::HttpProtocol(format!("Invalid URI: {}", e)))?;
        let method_http: http::Method = method
            .parse()
            .map_err(|_| Error::HttpProtocol("Invalid Method".into()))?;

        handle
            .send_request(method_http, &uri, headers_string, body_bytes)
            .await
    }

    fn create_quic_config(&self) -> Result<quiche::Config> {
        let mut config = if let Some(ref fp) = self.tls_fingerprint {
            // Use BoringSSL context builder for TLS fingerprinting
            use boring::ssl::{SslContextBuilder, SslMethod};

            let mut ssl_ctx_builder = SslContextBuilder::new(SslMethod::tls_client())
                .map_err(|e| Error::Tls(format!("Failed to create SSL context: {}", e)))?;

            // TLS 1.3 cipher suites (TLS_AES_128_GCM_SHA256, etc.) are not configurable
            // as they are determined by the QUIC implementation.
            // via set_cipher_list() in BoringSSL. QUIC uses TLS 1.3 exclusively.

            // Apply TLS 1.2 cipher suites only if they look like TLS 1.2 names (contain ECDHE/RSA/etc)
            let tls12_ciphers: Vec<&str> = fp
                .cipher_list
                .iter()
                .filter(|c| !c.starts_with("TLS_"))
                .map(|s| s.as_ref())
                .collect();
            if !tls12_ciphers.is_empty() {
                let cipher_str = tls12_ciphers.join(":");
                ssl_ctx_builder
                    .set_cipher_list(&cipher_str)
                    .map_err(|e| Error::Tls(format!("Failed to set cipher list: {}", e)))?;
            }

            // Apply curves/groups
            // If Kyber is enabled, prepend X25519Kyber768Draft00 to the curves list
            if !fp.curves.is_empty() {
                let curves_str = if fp.enable_kyber {
                    format!("X25519Kyber768Draft00:{}", fp.curves.join(":"))
                } else {
                    fp.curves.join(":")
                };
                ssl_ctx_builder
                    .set_curves_list(&curves_str)
                    .map_err(|e| Error::Tls(format!("Failed to set curves: {}", e)))?;
            } else if fp.enable_kyber {
                // If no curves specified but Kyber is enabled, set Kyber as the only group
                ssl_ctx_builder
                    .set_curves_list("X25519Kyber768Draft00")
                    .map_err(|e| Error::Tls(format!("Failed to set curves: {}", e)))?;
            }

            // Apply signature algorithms
            if !fp.sigalgs.is_empty() {
                let sigalgs_str = fp.sigalgs.join(":");
                ssl_ctx_builder
                    .set_sigalgs_list(&sigalgs_str)
                    .map_err(|e| {
                        Error::Tls(format!("Failed to set signature algorithms: {}", e))
                    })?;
            }

            // Create config with custom SSL context
            quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl_ctx_builder)
                .map_err(|e| {
                Error::Quic(format!(
                    "Failed to create quiche config with TLS fingerprint: {}",
                    e
                ))
            })?
        } else {
            quiche::Config::new(quiche::PROTOCOL_VERSION)
                .map_err(|e| Error::Quic(format!("Failed to create quiche config: {}", e)))?
        };

        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .map_err(|e| Error::Quic(format!("Failed to set ALPN: {}", e)))?;

        // Configure QUIC parameters to match Chrome behavior
        // Chrome uses 15663105 (15MB) for initial_max_data
        const CHROME_INITIAL_MAX_DATA: u64 = 15_663_105;

        config.set_max_idle_timeout(30_000);
        config.set_max_recv_udp_payload_size(65535);
        config.set_max_send_udp_payload_size(1350);
        config.set_initial_max_data(CHROME_INITIAL_MAX_DATA);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);

        Ok(config)
    }
}

fn parse_url_host(url: &str) -> Result<(String, u16, String)> {
    let u = url::Url::parse(url).map_err(|e| Error::Connection(e.to_string()))?;
    let host = u.host_str().unwrap_or("").to_string();
    Ok((host, 0, "".into()))
}
