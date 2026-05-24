//! HTTP/3 Connection establishment and management.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

use crate::error::{Error, Result};
use crate::fingerprint::{Http3Fingerprint, TlsFingerprint};
use crate::transport::dns::DnsConfig;
use crate::transport::h3::handle::H3Handle;
use crate::transport::h3::handshake::NativeQuicHandshake;
use crate::transport::h3::quic::ConnectionId;
use crate::transport::h3::recovery::{LossDetectionOutcome, PacketNumberSpace};
use crate::transport::h3::session_cache::{NativeH3SessionCache, NativeH3SessionCacheKey};
use crate::transport::h3::H3TransportConfig;

use crate::transport::h3::native_driver::spawn_native_h3_driver;
use bytes::Bytes;
use getrandom::fill as getrandom_fill;

const MAX_CONNECTION_ID_LEN: usize = 20;
const H3_UDP_SOCKET_BUFFER_BYTES: usize = 4 * 1024 * 1024;

pub struct H3Connection;

struct NativeH3Connect {
    host: String,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    tls_fingerprint: Option<TlsFingerprint>,
    fingerprint: Http3Fingerprint,
    max_idle_timeout: u64,
    verify_peer: bool,
    root_certs: Vec<Vec<u8>>,
    use_platform_roots: bool,
    transport_config: H3TransportConfig,
    session_cache: NativeH3SessionCache,
    session_cache_key: NativeH3SessionCacheKey,
}

impl H3Connection {
    /// Connect to an HTTP/3 server and return a handle.
    /// This spawns a background driver task.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        url: &str,
        tls_fingerprint: Option<TlsFingerprint>,
        fingerprint: Http3Fingerprint,
        max_idle_timeout: u64,
        verify_peer: bool,
        root_certs: Vec<Vec<u8>>,
        use_platform_roots: bool,
        dns_config: &DnsConfig,
        transport_config: H3TransportConfig,
        session_cache: NativeH3SessionCache,
        session_cache_key: NativeH3SessionCacheKey,
    ) -> Result<H3Handle> {
        let (host, port, _path) = parse_url(url)?;

        // Resolve peer
        let peer_addr = dns_config
            .resolve(&host, port)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::Connection("DNS/IP not found".into()))?;

        // Bind local socket
        let local_addr: SocketAddr = if peer_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = Arc::new(bind_udp_socket(local_addr)?);

        Self::connect_native(NativeH3Connect {
            host,
            socket,
            peer_addr,
            tls_fingerprint,
            fingerprint,
            max_idle_timeout,
            verify_peer,
            root_certs,
            use_platform_roots,
            transport_config,
            session_cache,
            session_cache_key,
        })
        .await
    }

    async fn connect_native(request: NativeH3Connect) -> Result<H3Handle> {
        let NativeH3Connect {
            host,
            socket,
            peer_addr,
            tls_fingerprint,
            fingerprint,
            max_idle_timeout,
            verify_peer,
            root_certs,
            use_platform_roots,
            transport_config,
            session_cache,
            session_cache_key,
        } = request;
        let destination_cid =
            random_connection_id(fingerprint.transport.destination_connection_id_len)?;
        let source_cid = random_connection_id(fingerprint.transport.source_connection_id_len)?;

        let cached_session = session_cache.get(&session_cache_key);
        let mut handshake = match NativeQuicHandshake::client_with_tls_fingerprint_and_session(
            &host,
            &fingerprint,
            tls_fingerprint.as_ref(),
            destination_cid,
            source_cid,
            verify_peer,
            &root_certs,
            use_platform_roots,
            cached_session.as_ref().map(|entry| entry.der.as_ref()),
        ) {
            Ok(handshake) => handshake,
            Err(err) if cached_session.is_some() => {
                session_cache.evict(&session_cache_key);
                NativeQuicHandshake::client_with_tls_fingerprint(
                    &host,
                    &fingerprint,
                    tls_fingerprint.as_ref(),
                    random_connection_id(fingerprint.transport.destination_connection_id_len)?,
                    random_connection_id(fingerprint.transport.source_connection_id_len)?,
                    verify_peer,
                    &root_certs,
                    use_platform_roots,
                )
                .map_err(|_| err)?
            }
            Err(err) => return Err(err),
        };

        socket
            .send_to(handshake.client_initial().packet.as_ref(), peer_addr)
            .await
            .map_err(Error::Io)?;
        handshake.record_client_initial_sent_at(Instant::now());

        let deadline = Instant::now() + Duration::from_millis(max_idle_timeout.max(1));
        let mut buf = vec![0u8; fingerprint.transport.max_recv_udp_payload_size.max(1200)];

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Error::Timeout("native H3 handshake timeout".into()));
            }

            let loss_detection_wait = handshake
                .loss_detection_timer()
                .map(|deadline| deadline.saturating_duration_since(Instant::now()));
            let recv_wait = loss_detection_wait
                .unwrap_or_else(|| Duration::from_millis(25))
                .min(Duration::from_millis(25))
                .min(remaining);

            match tokio::time::timeout(recv_wait, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, from))) if from == peer_addr => {
                    if buf[..len].first().is_some_and(|first| first & 0x80 == 0) {
                        if handshake.is_application_ready() {
                            return spawn_native_h3_driver(
                                handshake,
                                fingerprint,
                                socket,
                                peer_addr,
                                max_idle_timeout,
                                Some(Bytes::copy_from_slice(&buf[..len])),
                                transport_config,
                                session_cache.clone(),
                                session_cache_key.clone(),
                            );
                        }
                        continue;
                    }
                    let processed_packets = handshake.process_server_datagram(&buf[..len])?;
                    if let Some(packet) = handshake.take_pending_client_initial() {
                        socket
                            .send_to(packet.packet.as_ref(), peer_addr)
                            .await
                            .map_err(Error::Io)?;
                        handshake.record_client_initial_sent_at(Instant::now());
                    }
                    if let Some(packet) = handshake.build_client_initial_ack_packet()? {
                        socket
                            .send_to(packet.packet.as_ref(), peer_addr)
                            .await
                            .map_err(Error::Io)?;
                    }
                    if let Some(packet) = handshake.build_client_handshake_ack_packet()? {
                        socket
                            .send_to(packet.packet.as_ref(), peer_addr)
                            .await
                            .map_err(Error::Io)?;
                    }
                    for processed in processed_packets {
                        if let Some(packet) = handshake
                            .build_client_handshake_crypto_packet(processed.handshake_crypto_out)?
                        {
                            socket
                                .send_to(packet.packet.as_ref(), peer_addr)
                                .await
                                .map_err(Error::Io)?;
                        }
                    }
                    if handshake.is_application_ready() {
                        return spawn_native_h3_driver(
                            handshake,
                            fingerprint,
                            socket,
                            peer_addr,
                            max_idle_timeout,
                            None,
                            transport_config,
                            session_cache.clone(),
                            session_cache_key.clone(),
                        );
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(err)) => return Err(Error::Io(err)),
                Err(_) => {
                    Self::handle_client_loss_detection_timeout(
                        &mut handshake,
                        socket.as_ref(),
                        peer_addr,
                    )
                    .await?;
                }
            }
        }
    }

    async fn handle_client_loss_detection_timeout(
        handshake: &mut NativeQuicHandshake,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let Some(timer) = handshake.loss_detection_timer() else {
            return Ok(());
        };
        let now = Instant::now();
        if now < timer {
            return Ok(());
        }

        let pto = handshake.application_pto();
        match handshake.on_loss_detection_timeout(now) {
            LossDetectionOutcome::Pto {
                space: PacketNumberSpace::Initial,
            } => {
                for packet in handshake.retransmit_pto_client_initial_crypto_packets(now, pto)? {
                    socket
                        .send_to(packet.packet.as_ref(), peer_addr)
                        .await
                        .map_err(Error::Io)?;
                }
            }
            LossDetectionOutcome::Pto {
                space: PacketNumberSpace::Handshake,
            } => {
                for packet in handshake.retransmit_pto_client_handshake_crypto_packets(now, pto)? {
                    socket
                        .send_to(packet.packet.as_ref(), peer_addr)
                        .await
                        .map_err(Error::Io)?;
                }
            }
            LossDetectionOutcome::Pto {
                space: PacketNumberSpace::Application,
            }
            | LossDetectionOutcome::Loss { .. }
            | LossDetectionOutcome::Idle => {}
        }
        Ok(())
    }
}

fn random_connection_id(len: usize) -> Result<ConnectionId> {
    if len > MAX_CONNECTION_ID_LEN {
        return Err(Error::Quic(format!(
            "QUIC connection id length exceeds {MAX_CONNECTION_ID_LEN} bytes"
        )));
    }
    let mut bytes = vec![0u8; len];
    getrandom_fill(&mut bytes).map_err(|e| Error::Quic(format!("RNG error: {}", e)))?;
    ConnectionId::from_bytes(Bytes::from(bytes))
}

fn bind_udp_socket(local_addr: SocketAddr) -> Result<UdpSocket> {
    let domain = if local_addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .map_err(Error::Io)?;
    let _ = socket.set_recv_buffer_size(H3_UDP_SOCKET_BUFFER_BYTES);
    let _ = socket.set_send_buffer_size(H3_UDP_SOCKET_BUFFER_BYTES);
    socket.set_nonblocking(true).map_err(Error::Io)?;
    socket.bind(&local_addr.into()).map_err(Error::Io)?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).map_err(Error::Io)
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
