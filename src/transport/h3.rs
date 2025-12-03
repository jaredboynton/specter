//! HTTP/3 transport via quiche.

use bytes::Bytes;
use getrandom::fill as getrandom_fill;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};
use url::Url;

use crate::error::{Error, Result};
use crate::fingerprint::tls::TlsFingerprint;
use crate::response::Response;

// Import NameValue trait for Header name/value access
use quiche::h3::NameValue;

/// HTTP/3 client using quiche QUIC transport.
#[derive(Debug, Clone)]
pub struct H3Client {
    tls_fingerprint: Option<TlsFingerprint>,
    max_idle_timeout: u64,
    max_udp_payload_size: usize,
}

impl Default for H3Client {
    fn default() -> Self {
        Self::new()
    }
}

impl H3Client {
    /// Create a new H3Client with default settings.
    pub fn new() -> Self {
        Self {
            tls_fingerprint: None,
            max_idle_timeout: QUIC_IDLE_TIMEOUT_MS,
            max_udp_payload_size: MAX_DATAGRAM_SIZE,
        }
    }

    /// Create an H3Client with TLS fingerprint configuration.
    pub fn with_fingerprint(fingerprint: TlsFingerprint) -> Self {
        Self {
            tls_fingerprint: Some(fingerprint),
            max_idle_timeout: QUIC_IDLE_TIMEOUT_MS,
            max_udp_payload_size: MAX_DATAGRAM_SIZE,
        }
    }

    /// Configure quiche QUIC connection settings.
    fn configure_quic(&self) -> Result<quiche::Config> {
        let mut config = if let Some(ref fp) = self.tls_fingerprint {
            // Use BoringSSL context builder for TLS fingerprinting
            use boring::ssl::{SslContextBuilder, SslMethod};

            let mut ssl_ctx_builder = SslContextBuilder::new(SslMethod::tls_client())
                .map_err(|e| Error::Tls(format!("Failed to create SSL context: {}", e)))?;

            // NOTE: TLS 1.3 cipher suites (TLS_AES_128_GCM_SHA256 etc.) are NOT configurable
            // via set_cipher_list() in BoringSSL. QUIC uses TLS 1.3 exclusively, and TLS 1.3
            // ciphersuites are fixed by the protocol. Skip cipher configuration for HTTP/3.
            // The cipher_list in TlsFingerprint is intended for TLS 1.2 connections only.

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
            if !fp.curves.is_empty() {
                let curves_str = fp.curves.join(":");
                ssl_ctx_builder
                    .set_curves_list(&curves_str)
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

        // Set application protocol to HTTP/3
        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .map_err(|e| Error::Quic(format!("Failed to set ALPN: {}", e)))?;

        // Configure QUIC parameters
        config.set_max_idle_timeout(self.max_idle_timeout);
        config.set_max_recv_udp_payload_size(65535);
        config.set_max_send_udp_payload_size(self.max_udp_payload_size);
        config.set_initial_max_data(INITIAL_MAX_DATA);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);

        Ok(config)
    }

    /// Send an HTTP/3 request.
    pub async fn send_request(
        &self,
        url: &str,
        method: &str,
        headers: Vec<(&str, &str)>,
        body: Option<Vec<u8>>,
    ) -> Result<Response> {
        // Parse URL
        let (host, port, path) = parse_url(url)?;

        // Resolve peer address
        let peer_addr = tokio::net::lookup_host(format!("{}:{}", host, port))
            .await
            .map_err(|e| Error::Connection(format!("Failed to resolve {}:{}: {}", host, port, e)))?
            .next()
            .ok_or_else(|| Error::Connection(format!("No address found for {}:{}", host, port)))?;

        // Create UDP socket
        let local_addr: SocketAddr = "0.0.0.0:0"
            .parse()
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;

        let socket = UdpSocket::bind(local_addr).await.map_err(Error::Io)?;

        // Generate connection ID
        let scid_bytes = generate_cid()?;
        let scid = quiche::ConnectionId::from_ref(&scid_bytes);

        // Get QUIC config
        let mut config = self.configure_quic()?;

        // Create QUIC connection using quiche::connect
        let mut conn = quiche::connect(
            Some(&host),
            &scid,
            socket.local_addr().map_err(Error::Io)?,
            peer_addr,
            &mut config,
        )
        .map_err(|e| Error::Quic(format!("Failed to create QUIC connection: {}", e)))?;

        // Perform QUIC handshake
        let handshake_timeout = Duration::from_secs(30);
        let handshake_start = Instant::now();

        loop {
            if handshake_start.elapsed() > handshake_timeout {
                let stats = conn.stats();
                return Err(Error::Timeout(format!(
                    "QUIC handshake timed out: sent={}, recv={}, lost={}, closed={}",
                    stats.sent,
                    stats.recv,
                    stats.lost,
                    conn.is_closed()
                )));
            }

            // Flush egress packets
            flush_egress(&mut conn, &socket, peer_addr).await?;

            // Check if connection is established
            if conn.is_established() {
                break;
            }

            // Check if connection was closed (e.g., TLS error)
            if conn.is_closed() {
                let peer_err = conn.peer_error();
                return Err(Error::Quic(format!(
                    "QUIC connection closed during handshake: {:?}",
                    peer_err
                )));
            }

            // Receive ingress packets with timeout
            let recv_timeout = Duration::from_millis(100);
            match timeout(recv_timeout, recv_ingress(&socket, &mut conn)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    // Timeout - continue handshake loop (with delay below)
                }
            }

            // Small delay to avoid busy loop
            sleep(Duration::from_millis(10)).await;
        }

        // Create HTTP/3 connection
        let h3_config = quiche::h3::Config::new()
            .map_err(|e| Error::Quic(format!("Failed to create HTTP/3 config: {}", e)))?;

        let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)
            .map_err(|e| Error::Quic(format!("Failed to create HTTP/3 connection: {}", e)))?;

        // Build HTTP/3 headers
        let mut h3_headers = vec![
            (":method", method.as_bytes()),
            (":scheme", b"https"),
            (":authority", host.as_bytes()),
            (":path", path.as_bytes()),
        ];

        // Add custom headers (convert to bytes), filtering out:
        // 1. Pseudo-headers (start with ':') - we already set these above
        // 2. Connection-specific headers forbidden in HTTP/3 (RFC 9114 Section 4.2)
        let mut custom_headers: Vec<(&str, &[u8])> = headers
            .iter()
            .filter(|(k, _)| {
                let name_lower = k.to_lowercase();
                !k.starts_with(':')
                    && name_lower != "connection"
                    && name_lower != "keep-alive"
                    && name_lower != "proxy-connection"
                    && name_lower != "transfer-encoding"
                    && name_lower != "upgrade"
            })
            .map(|(k, v)| (*k, v.as_bytes()))
            .collect();
        h3_headers.append(&mut custom_headers);

        // Convert headers to quiche format
        let quiche_headers: Vec<quiche::h3::Header> = h3_headers
            .iter()
            .map(|(name, value)| quiche::h3::Header::new(name.as_bytes(), value))
            .collect();

        // Send HTTP/3 request
        let stream_id = h3_conn
            .send_request(&mut conn, &quiche_headers, body.is_none())
            .map_err(|e| Error::Quic(format!("Failed to send HTTP/3 request: {}", e)))?;

        // Send body if present
        if let Some(ref body_data) = body {
            h3_conn
                .send_body(&mut conn, stream_id, body_data, true)
                .map_err(|e| Error::Quic(format!("Failed to send HTTP/3 body: {}", e)))?;
        }

        // Flush the request to the network
        flush_egress(&mut conn, &socket, peer_addr).await?;

        // Poll for response
        let response_timeout = Duration::from_secs(30);
        let response_start = Instant::now();

        let mut response_headers: Vec<String> = Vec::new();
        let mut response_body: Vec<u8> = Vec::new();
        let mut status_code: Option<u16> = None;
        let mut stream_finished = false;

        loop {
            if response_start.elapsed() > response_timeout {
                return Err(Error::Timeout("HTTP/3 response timed out".into()));
            }

            // 1. RECEIVE: Get all available packets from network
            while let Ok(Ok(_)) =
                timeout(Duration::from_millis(1), recv_ingress(&socket, &mut conn)).await
            {
                // Keep receiving
            }

            // 2. POLL: Process received packets as HTTP/3 events
            loop {
                match h3_conn.poll(&mut conn) {
                    Ok((id, quiche::h3::Event::Headers { list, .. })) => {
                        if id == stream_id {
                            for header in list {
                                let name_bytes = header.name();
                                let value_bytes = header.value();
                                let name = String::from_utf8_lossy(name_bytes);
                                let value = String::from_utf8_lossy(value_bytes);

                                if name == ":status" {
                                    status_code = value.parse().ok();
                                }

                                response_headers.push(format!("{}: {}", name, value));
                            }
                        }
                    }
                    Ok((id, quiche::h3::Event::Data)) => {
                        if id == stream_id {
                            let mut buf = vec![0u8; 65535];
                            while let Ok(amount) = h3_conn.recv_body(&mut conn, stream_id, &mut buf)
                            {
                                if amount == 0 {
                                    break;
                                }
                                response_body.extend_from_slice(&buf[..amount]);
                            }
                        }
                    }
                    Ok((id, quiche::h3::Event::Finished)) => {
                        if id == stream_id {
                            stream_finished = true;
                        }
                    }
                    Ok((_, quiche::h3::Event::Reset { .. })) => {
                        return Err(Error::HttpProtocol("HTTP/3 stream reset".into()));
                    }
                    Ok((_, quiche::h3::Event::PriorityUpdate)) => {}
                    Ok((_, quiche::h3::Event::GoAway)) => {
                        return Err(Error::HttpProtocol("HTTP/3 GOAWAY received".into()));
                    }
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => {
                        return Err(Error::Quic(format!("HTTP/3 poll error: {}", e)));
                    }
                }
            }

            // Check if we're done
            if stream_finished && status_code.is_some() {
                break;
            }

            // 3. SEND: Flush any outgoing packets (ACKs, etc)
            flush_egress(&mut conn, &socket, peer_addr).await?;

            // Small delay before next iteration
            sleep(Duration::from_millis(10)).await;
        }

        // Build Response
        let status = status_code.unwrap_or(0);
        let body_bytes = Bytes::from(response_body);

        Ok(Response::new(
            status,
            response_headers,
            body_bytes,
            "HTTP/3".to_string(),
        ))
    }
}

/// Generate a random connection ID.
fn generate_cid() -> Result<Vec<u8>> {
    let mut cid = vec![0u8; 20];
    getrandom_fill(&mut cid)
        .map_err(|e| Error::Quic(format!("Failed to generate connection ID: {}", e)))?;
    Ok(cid)
}

/// Parse URL and extract host, port, and path.
fn parse_url(url: &str) -> Result<(String, u16, String)> {
    let parsed = Url::parse(url)?;

    // Validate scheme
    if parsed.scheme() != "https" {
        return Err(Error::HttpProtocol(format!(
            "Unsupported scheme: {}, only https:// is supported for HTTP/3",
            parsed.scheme()
        )));
    }

    // Extract host
    let host = parsed
        .host_str()
        .ok_or_else(|| Error::Missing("URL must have a host".into()))?
        .to_string();

    // Extract port (default 443 for https)
    let port = parsed.port().unwrap_or(443);

    // Extract path (default to /)
    let path = parsed.path();
    let path = if path.is_empty() { "/" } else { path };

    Ok((host, port, path.to_string()))
}

/// Flush egress packets from QUIC connection to UDP socket.
async fn flush_egress(
    conn: &mut quiche::Connection,
    socket: &UdpSocket,
    peer: SocketAddr,
) -> Result<()> {
    loop {
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
        match conn.send(&mut out) {
            Ok((len, _info)) => {
                if len > 0 {
                    socket.send_to(&out[..len], peer).await.map_err(Error::Io)?;
                } else {
                    break;
                }
            }
            Err(quiche::Error::Done) => {
                break;
            }
            Err(e) => {
                return Err(Error::Quic(format!("Failed to send QUIC packet: {}", e)));
            }
        }
    }
    Ok(())
}

/// Receive ingress packets from UDP socket and process with QUIC connection.
async fn recv_ingress(socket: &UdpSocket, conn: &mut quiche::Connection) -> Result<()> {
    let mut buf = vec![0u8; 65535];

    match socket.recv_from(&mut buf).await {
        Ok((len, from)) => {
            let recv_info = quiche::RecvInfo {
                from,
                to: socket.local_addr().map_err(Error::Io)?,
            };

            match conn.recv(&mut buf[..len], recv_info) {
                Ok(_) => Ok(()),
                Err(quiche::Error::Done) => Ok(()),
                Err(e) => Err(Error::Quic(format!("Failed to process QUIC packet: {}", e))),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Maximum datagram size for QUIC.
const MAX_DATAGRAM_SIZE: usize = 1350;

/// QUIC idle timeout in milliseconds.
const QUIC_IDLE_TIMEOUT_MS: u64 = 30_000;

/// Initial maximum data for QUIC connection.
const INITIAL_MAX_DATA: u64 = 10_000_000;
