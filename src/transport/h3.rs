//! HTTP/3 transport via quiche.

use std::net::{ToSocketAddrs, SocketAddr};
use std::time::{Duration, Instant};
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::time::{timeout, sleep};
use url::Url;
use getrandom::getrandom;

use crate::fingerprint::tls::TlsFingerprint;
use crate::response::Response;
use crate::error::{Error, Result};

// Import NameValue trait for Header name/value access
use quiche::h3::NameValue;

/// HTTP/3 client using quiche QUIC transport.
#[derive(Debug, Clone)]
pub struct H3Client {
    tls_fingerprint: Option<TlsFingerprint>,
    max_idle_timeout: u64,
    max_udp_payload_size: usize,
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
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|e| Error::Quic(format!("Failed to create quiche config: {}", e)))?;

        // Set application protocol to HTTP/3
        // APPLICATION_PROTOCOL is &[&[u8]], so we pass it directly
        config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL);

        // Configure QUIC parameters
        config.set_max_idle_timeout(QUIC_IDLE_TIMEOUT_MS);
        config.set_max_recv_udp_payload_size(65535);
        config.set_max_send_udp_payload_size(self.max_udp_payload_size);
        config.set_initial_max_data(INITIAL_MAX_DATA);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_disable_active_migration(true);

        // Note: TLS fingerprint configuration for quiche is complex as quiche uses BoringSSL
        // internally. The TLS fingerprint would need to be applied at the BoringSSL level
        // which quiche doesn't expose directly. For now, we accept the fingerprint but
        // note that full fingerprint control requires quiche API changes.
        if self.tls_fingerprint.is_some() {
            // TLS fingerprint is stored but quiche doesn't expose BoringSSL configuration
            // This would require custom quiche build or API extensions
            tracing::warn!("TLS fingerprint specified but quiche doesn't expose BoringSSL config");
        }

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
        let peer_addr = format!("{}:{}", host, port)
            .to_socket_addrs()
            .map_err(|e| Error::Connection(format!("Failed to resolve {}:{}: {}", host, port, e)))?
            .next()
            .ok_or_else(|| Error::Connection(format!("No address found for {}:{}", host, port)))?;

        // Create UDP socket
        let local_addr: SocketAddr = "0.0.0.0:0".parse()
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;

        let socket = UdpSocket::bind(local_addr).await
            .map_err(|e| Error::Io(e))?;

        // Generate connection ID
        let scid_bytes = generate_cid()?;
        let scid = quiche::ConnectionId::from_ref(&scid_bytes);

        // Get QUIC config
        let mut config = self.configure_quic()?;

        // Create QUIC connection using quiche::connect
        let mut conn = quiche::connect(
            Some(&host),
            &scid,
            socket.local_addr().map_err(|e| Error::Io(e))?,
            peer_addr,
            &mut config,
        )
        .map_err(|e| Error::Quic(format!("Failed to create QUIC connection: {}", e)))?;

        // Perform QUIC handshake
        let handshake_timeout = Duration::from_secs(30);
        let handshake_start = Instant::now();

        loop {
            if handshake_start.elapsed() > handshake_timeout {
                return Err(Error::Timeout("QUIC handshake timed out".into()));
            }

            // Flush egress packets
            flush_egress(&mut conn, &socket, peer_addr).await?;

            // Check if connection is established
            if conn.is_established() {
                break;
            }

            // Receive ingress packets with timeout
            let recv_timeout = Duration::from_millis(100);
            match timeout(recv_timeout, recv_ingress(&socket, &mut conn)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    // Timeout - continue handshake loop
                    continue;
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

        // Add custom headers (convert to bytes)
        let mut custom_headers: Vec<(&str, &[u8])> = headers
            .iter()
            .map(|(k, v)| (*k, v.as_bytes()))
            .collect();
        h3_headers.append(&mut custom_headers);

        // Convert headers to quiche format
        let quiche_headers: Vec<quiche::h3::Header> = h3_headers
            .iter()
            .map(|(name, value)| quiche::h3::Header::new(name.as_bytes(), value))
            .collect();

        // Send HTTP/3 request
        let stream_id = h3_conn.send_request(&mut conn, &quiche_headers, body.is_none())
            .map_err(|e| Error::Quic(format!("Failed to send HTTP/3 request: {}", e)))?;

        // Send body if present
        if let Some(ref body_data) = body {
            h3_conn.send_body(&mut conn, stream_id, body_data, true)
                .map_err(|e| Error::Quic(format!("Failed to send HTTP/3 body: {}", e)))?;
        }

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

            // Flush egress packets
            flush_egress(&mut conn, &socket, peer_addr).await?;

            // Poll HTTP/3 events
            loop {
                match h3_conn.poll(&mut conn) {
                    Ok((id, quiche::h3::Event::Headers { list, .. })) => {
                        if id == stream_id {
                            // Parse headers - Header implements the Header trait
                            for header in list {
                                // Access header name and value via trait methods
                                let name_bytes = header.name();
                                let value_bytes = header.value();
                                let name = String::from_utf8_lossy(name_bytes);
                                let value = String::from_utf8_lossy(value_bytes);
                                
                                // Extract status code from :status pseudo-header
                                if name == ":status" {
                                    status_code = value.parse().ok();
                                }
                                
                                response_headers.push(format!("{}: {}", name, value));
                            }
                        }
                    }
                    Ok((id, quiche::h3::Event::Data)) => {
                        if id == stream_id {
                            // Read response body
                            let mut buf = vec![0u8; 65535];
                            match h3_conn.recv_body(&mut conn, stream_id, &mut buf) {
                                Ok(amount) => {
                                    if amount > 0 {
                                        response_body.extend_from_slice(&buf[..amount]);
                                    }
                                }
                                Err(quiche::h3::Error::Done) => {
                                    // No more data available
                                }
                                Err(e) => {
                                    return Err(Error::Quic(format!("Failed to read HTTP/3 body: {}", e)));
                                }
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
                    Ok((_, quiche::h3::Event::PriorityUpdate { .. })) => {
                        // Ignore priority update events
                    }
                    Ok((_, quiche::h3::Event::GoAway { .. })) => {
                        // Server sent GOAWAY, connection closing
                        return Err(Error::HttpProtocol("HTTP/3 GOAWAY received".into()));
                    }
                    Err(quiche::h3::Error::Done) => {
                        // No more events
                        break;
                    }
                    Err(e) => {
                        return Err(Error::Quic(format!("HTTP/3 poll error: {}", e)));
                    }
                }
            }

            // Check if we're done
            if stream_finished && status_code.is_some() {
                break;
            }

            // Receive ingress packets
            let recv_timeout = Duration::from_millis(100);
            match timeout(recv_timeout, recv_ingress(&socket, &mut conn)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    // Timeout - continue polling
                    continue;
                }
            }

            // Small delay to avoid busy loop
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
    getrandom(&mut cid)
        .map_err(|e| Error::Quic(format!("Failed to generate connection ID: {}", e)))?;
    Ok(cid)
}

/// Parse URL and extract host, port, and path.
fn parse_url(url: &str) -> Result<(String, u16, String)> {
    let parsed = Url::parse(url)?;

    // Validate scheme
    if parsed.scheme() != "https" {
        return Err(Error::HttpProtocol(format!("Unsupported scheme: {}, only https:// is supported for HTTP/3", parsed.scheme())));
    }

    // Extract host
    let host = parsed.host_str()
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
                    socket.send_to(&out[..len], peer).await
                        .map_err(|e| Error::Io(e))?;
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
async fn recv_ingress(
    socket: &UdpSocket,
    conn: &mut quiche::Connection,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    
    match socket.recv_from(&mut buf).await {
        Ok((len, from)) => {
            let recv_info = quiche::RecvInfo {
                from,
                to: socket.local_addr()
                    .map_err(|e| Error::Io(e))?,
            };

            match conn.recv(&mut buf[..len], recv_info) {
                Ok(_) => Ok(()),
                Err(quiche::Error::Done) => Ok(()),
                Err(e) => Err(Error::Quic(format!("Failed to process QUIC packet: {}", e))),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            Ok(())
        }
        Err(e) => Err(Error::Io(e)),
    }
}

/// Maximum datagram size for QUIC.
const MAX_DATAGRAM_SIZE: usize = 1350;

/// QUIC idle timeout in milliseconds.
const QUIC_IDLE_TIMEOUT_MS: u64 = 30_000;

/// Initial maximum data for QUIC connection.
const INITIAL_MAX_DATA: u64 = 10_000_000;
