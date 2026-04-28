use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::net::{TcpStream, UdpSocket};

/// Object-safe trait for QUIC UDP transport, supporting both direct and
/// SOCKS5-proxied UDP paths.
#[allow(clippy::type_complexity)]
pub(crate) trait QuicUdpTransport: Send + Sync {
    fn send_to_target<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;

    fn recv_from_target<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>>;

    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// Transparent pass-through over a raw `UdpSocket`.
pub(crate) struct DirectUdpTransport {
    socket: Arc<UdpSocket>,
}

impl DirectUdpTransport {
    pub(crate) fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket }
    }

    #[allow(dead_code)]
    pub(crate) fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }
}

impl QuicUdpTransport for DirectUdpTransport {
    fn send_to_target<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move { self.socket.send_to(buf, target).await })
    }

    fn recv_from_target<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move { self.socket.recv_from(buf).await })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

/// UDP transport through a SOCKS5 UDP ASSOCIATE relay.
///
/// The `_control` TCP stream must remain alive for the duration of the
/// association — dropping it signals the SOCKS5 server to tear down the
/// UDP relay.
pub(crate) struct Socks5UdpTransport {
    socket: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    _control: TcpStream,
}

impl Socks5UdpTransport {
    pub(crate) fn new(socket: Arc<UdpSocket>, relay_addr: SocketAddr, control: TcpStream) -> Self {
        Self {
            socket,
            relay_addr,
            _control: control,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }
}

impl QuicUdpTransport for Socks5UdpTransport {
    fn send_to_target<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let wrapped = crate::proxy::socks5::encode_socks5_udp_header(target, buf);
            self.socket.send_to(&wrapped, self.relay_addr).await
        })
    }

    fn recv_from_target<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move {
            let mut internal_buf = [0u8; 65535];
            let (n, _relay) = self.socket.recv_from(&mut internal_buf).await?;
            let data = &internal_buf[..n];

            let (source_addr, header_len) = crate::proxy::socks5::decode_socks5_udp_header(data)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

            let payload = &data[header_len..];
            let copy_len = payload.len().min(buf.len());
            buf[..copy_len].copy_from_slice(&payload[..copy_len]);

            Ok((copy_len, source_addr))
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}
