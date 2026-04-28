//! HTTP/3 Connection establishment and management.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use crate::proxy::ProxyConfig;
use crate::proxy::udp_transport::{QuicUdpTransport, DirectUdpTransport, Socks5UdpTransport};
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::transport::h3::driver::H3Driver;
use crate::transport::h3::handle::H3Handle;

use getrandom::fill as getrandom_fill;
use quiche;

pub struct H3Connection;

impl H3Connection {
    /// Connect to an HTTP/3 server and return a handle.
    /// This spawns a background driver task.
    pub async fn connect(url: &str, mut config: quiche::Config, proxy: Option<&ProxyConfig>) -> Result<H3Handle> {
        let (host, port, _path) = parse_url(url)?;

        // Resolve peer
        let peer_addr = tokio::net::lookup_host(format!("{}:{}", host, port))
            .await
            .map_err(|e| Error::Connection(format!("DNS Resolve failed: {}", e)))?
            .next()
            .ok_or_else(|| Error::Connection("DNS/IP not found".into()))?;

        // Create UDP transport (direct or via SOCKS5 relay)
        let (transport, local_addr): (Box<dyn QuicUdpTransport>, SocketAddr) = match proxy {
            Some(ProxyConfig::Socks5 { host: ph, port: pp, auth }) => {
                let local_socket = UdpSocket::bind("0.0.0.0:0").await.map_err(Error::Io)?;
                let local_udp_addr = local_socket.local_addr().map_err(Error::Io)?;
                let local_socket = Arc::new(local_socket);

                let association = crate::proxy::socks5::socks5_udp_associate(
                    ph, *pp, local_udp_addr, auth.as_ref()
                ).await?;

                let addr = local_socket.local_addr().map_err(Error::Io)?;
                let transport = Socks5UdpTransport::new(local_socket, association.relay_addr, association.control_tcp);
                (Box::new(transport) as Box<dyn QuicUdpTransport>, addr)
            }
            _ => {
                // Direct UDP (original behavior); also covers HttpConnect (no UDP path for H3)
                let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(Error::Io)?;
                let addr = socket.local_addr().map_err(Error::Io)?;
                let socket = Arc::new(socket);
                (Box::new(DirectUdpTransport::new(socket)) as Box<dyn QuicUdpTransport>, addr)
            }
        };

        // Generate CID
        let mut scid = [0u8; 20];
        getrandom_fill(&mut scid).map_err(|e| Error::Quic(format!("RNG error: {}", e)))?;
        let scid = quiche::ConnectionId::from_ref(&scid);

        // Create QUIC connection
        let mut conn = quiche::connect(
            Some(&host),
            &scid,
            local_addr,
            peer_addr,
            &mut config,
        )
        .map_err(|e| Error::Quic(format!("Connect failed: {}", e)))?;

        // Handshake Loop
        // We must drive the handshake until established BEFORE spawning driver
        // to return errors early.
        let mut buf = vec![0u8; 65535];
        let mut out = vec![0u8; 1350];

        let start = Instant::now();
        let timeout_dur = std::time::Duration::from_secs(10);

        loop {
            if start.elapsed() > timeout_dur {
                return Err(Error::Timeout("H3 Handshake timeout".into()));
            }

            // Flush egress
            loop {
                match conn.send(&mut out) {
                    Ok((len, _)) => {
                        transport
                            .send_to_target(&out[..len], peer_addr)
                            .await
                            .map_err(Error::Io)?;
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => return Err(Error::Quic(format!("Send error: {}", e))),
                }
            }

            if conn.is_established() {
                break;
            }
            if conn.is_closed() {
                return Err(Error::Quic("Connection closed during handshake".into()));
            }

            // Recv ingress
            let recv_timeout = conn
                .timeout()
                .unwrap_or(std::time::Duration::from_millis(100));
            // Use small timeout for recv to allow sending keep-alives/re-transmits
            match tokio::time::timeout(recv_timeout, transport.recv_from_target(&mut buf)).await {
                Ok(Ok((len, from))) => {
                    let info = quiche::RecvInfo {
                        from,
                        to: transport.local_addr().unwrap(),
                    };
                    let _ = conn.recv(&mut buf[..len], info);
                }
                Ok(Err(e)) => return Err(Error::Io(e)),
                Err(_) => {
                    conn.on_timeout();
                }
            }
        }

        // Create HTTP/3 connection context
        let h3_config = quiche::h3::Config::new()
            .map_err(|e| Error::Quic(format!("H3 Config error: {}", e)))?;
        let h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)
            .map_err(|e| Error::Quic(format!("H3 Init error: {}", e)))?;

        // Spawn Driver
        let (tx, rx) = mpsc::channel(32);
        let driver = H3Driver::new(rx, conn, h3_conn, transport, peer_addr);

        tokio::spawn(async move {
            if let Err(e) = driver.drive().await {
                tracing::error!("H3 Driver crashed: {:?}", e);
            }
        });

        Ok(H3Handle::new(tx))
    }
}

fn parse_url(url: &str) -> Result<(String, u16, String)> {
    let u = url::Url::parse(url).map_err(|e| Error::CookieParse(e.to_string()))?;
    if u.scheme() != "https" {
        return Err(Error::Connection("HTTP/3 requires https".into()));
    }
    let host = u
        .host_str()
        .ok_or(Error::Connection("No host".into()))?
        .to_string();
    let port = u.port().unwrap_or(443);
    let path = u.path().to_string();
    Ok((host, port, path))
}
