//! SOCKS5 proxy implementation (RFC 1928 + RFC 1929).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::Error;
use crate::proxy::ProxyAuth;

// SOCKS5 constants
const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_USER_PASS: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const USERPASS_VERSION: u8 = 0x01;

/// Establish a TCP tunnel through a SOCKS5 proxy to the target host.
pub(crate) async fn socks5_connect(
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
    auth: Option<&ProxyAuth>,
) -> Result<TcpStream, Error> {
    if target_host.len() > 255 {
        return Err(Error::Connection(
            "SOCKS5: domain name exceeds 255 bytes".into(),
        ));
    }

    let mut stream = TcpStream::connect((proxy_host, proxy_port))
        .await
        .map_err(|e| Error::Connection(format!("SOCKS5: failed to connect to proxy: {}", e)))?;

    negotiate_auth(&mut stream, auth).await?;

    // CONNECT request: domain name (atyp=0x03, always remote DNS)
    let domain = target_host.as_bytes();
    let mut buf = Vec::with_capacity(7 + domain.len());
    buf.push(SOCKS5_VERSION);
    buf.push(CMD_CONNECT);
    buf.push(0x00); // reserved
    buf.push(ATYP_DOMAIN);
    buf.push(domain.len() as u8);
    buf.extend_from_slice(domain);
    buf.push((target_port >> 8) as u8);
    buf.push(target_port as u8);

    stream
        .write_all(&buf)
        .await
        .map_err(|e| Error::Connection(format!("SOCKS5: failed to send CONNECT: {}", e)))?;

    let rep = read_reply(&mut stream).await?;
    if rep != 0x00 {
        return Err(Error::Connection(format!(
            "SOCKS5 CONNECT failed: {}",
            reply_message(rep)
        )));
    }

    Ok(stream)
}

/// State for an active SOCKS5 UDP ASSOCIATE session.
pub(crate) struct Socks5UdpAssociation {
    /// The TCP control connection — must stay alive for the association to remain valid.
    pub control_tcp: TcpStream,
    /// The relay address to send UDP datagrams to.
    pub relay_addr: SocketAddr,
}

/// Request a SOCKS5 UDP ASSOCIATE through the proxy.
pub(crate) async fn socks5_udp_associate(
    proxy_host: &str,
    proxy_port: u16,
    local_udp_addr: SocketAddr,
    auth: Option<&ProxyAuth>,
) -> Result<Socks5UdpAssociation, Error> {
    let mut stream = TcpStream::connect((proxy_host, proxy_port))
        .await
        .map_err(|e| Error::Connection(format!("SOCKS5: failed to connect to proxy: {}", e)))?;

    negotiate_auth(&mut stream, auth).await?;

    // UDP ASSOCIATE request with local address (or 0.0.0.0:0 if unspecified)
    let addr = match local_udp_addr {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    };

    let ip = addr.ip().octets();
    let port = addr.port();
    let request = [
        SOCKS5_VERSION,
        CMD_UDP_ASSOCIATE,
        0x00, // reserved
        ATYP_IPV4,
        ip[0],
        ip[1],
        ip[2],
        ip[3],
        (port >> 8) as u8,
        port as u8,
    ];

    stream
        .write_all(&request)
        .await
        .map_err(|e| Error::Connection(format!("SOCKS5: failed to send UDP ASSOCIATE: {}", e)))?;

    let rep = read_reply_with_addr(&mut stream).await?;
    if rep.reply != 0x00 {
        return Err(Error::Connection(format!(
            "SOCKS5 UDP ASSOCIATE failed: {}",
            reply_message(rep.reply)
        )));
    }

    // If server returns 0.0.0.0, use the proxy host IP instead
    let relay_addr = match rep.bound_addr {
        SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
            let proxy_ip: Ipv4Addr = proxy_host.parse().unwrap_or(Ipv4Addr::new(127, 0, 0, 1));
            SocketAddr::V4(SocketAddrV4::new(proxy_ip, v4.port()))
        }
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
            let proxy_ip: Ipv4Addr = proxy_host.parse().unwrap_or(Ipv4Addr::new(127, 0, 0, 1));
            SocketAddr::V4(SocketAddrV4::new(proxy_ip, v6.port()))
        }
        other => other,
    };

    Ok(Socks5UdpAssociation {
        control_tcp: stream,
        relay_addr,
    })
}

/// Encode a SOCKS5 UDP relay header prepended to the payload.
///
/// Format: `[0x00, 0x00, 0x00, atyp, addr, port] ++ data`
pub(crate) fn encode_socks5_udp_header(target: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0x00); // RSV
    buf.push(0x00); // RSV
    buf.push(0x00); // FRAG (no fragmentation)

    match target {
        SocketAddr::V4(v4) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.ip().octets());
        }
    }

    let port = target.port();
    buf.push((port >> 8) as u8);
    buf.push(port as u8);
    buf.extend_from_slice(data);
    buf
}

/// Decode a SOCKS5 UDP relay header, returning the source address and the byte offset
/// where the payload data begins.
pub(crate) fn decode_socks5_udp_header(buf: &[u8]) -> Result<(SocketAddr, usize), Error> {
    // Minimum: 2 RSV + 1 FRAG + 1 ATYP + 4 addr (IPv4) + 2 port = 10
    if buf.len() < 10 {
        return Err(Error::Connection(
            "SOCKS5 UDP: packet too short for header".into(),
        ));
    }

    // buf[0..2] = RSV, buf[2] = FRAG
    let atyp = buf[3];
    match atyp {
        ATYP_IPV4 => {
            if buf.len() < 10 {
                return Err(Error::Connection(
                    "SOCKS5 UDP: packet too short for IPv4 header".into(),
                ));
            }
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Ok((SocketAddr::V4(SocketAddrV4::new(ip, port)), 10))
        }
        ATYP_DOMAIN => {
            if buf.len() < 5 {
                return Err(Error::Connection(
                    "SOCKS5 UDP: packet too short for domain header".into(),
                ));
            }
            let dlen = buf[4] as usize;
            let header_len = 4 + 1 + dlen + 2; // atyp offset + len byte + domain + port
            if buf.len() < header_len {
                return Err(Error::Connection(
                    "SOCKS5 UDP: packet too short for domain name".into(),
                ));
            }
            // For domain atyp in UDP response, we can't resolve here.
            // Return 0.0.0.0 with the port — caller must handle domain resolution.
            let port_offset = 4 + 1 + dlen;
            let port = u16::from_be_bytes([buf[port_offset], buf[port_offset + 1]]);
            Ok((
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)),
                header_len,
            ))
        }
        ATYP_IPV6 => {
            let header_len = 4 + 16 + 2; // 4 header bytes + 16 addr + 2 port
            if buf.len() < header_len {
                return Err(Error::Connection(
                    "SOCKS5 UDP: packet too short for IPv6 header".into(),
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Ok((
                SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)),
                header_len,
            ))
        }
        _ => Err(Error::Connection(format!(
            "SOCKS5 UDP: unsupported address type 0x{:02x}",
            atyp
        ))),
    }
}

// --- Internal helpers ---

/// Negotiate SOCKS5 authentication with the proxy.
async fn negotiate_auth(stream: &mut TcpStream, auth: Option<&ProxyAuth>) -> Result<(), Error> {
    // Validate credentials length before sending anything
    if let Some(a) = auth {
        if a.username.len() > 255 {
            return Err(Error::Connection(
                "SOCKS5: username exceeds 255 bytes".into(),
            ));
        }
        if a.password.len() > 255 {
            return Err(Error::Connection(
                "SOCKS5: password exceeds 255 bytes".into(),
            ));
        }
    }

    // Greeting: offer methods
    let greeting = if auth.is_some() {
        vec![SOCKS5_VERSION, 2, AUTH_NONE, AUTH_USER_PASS]
    } else {
        vec![SOCKS5_VERSION, 1, AUTH_NONE]
    };

    stream
        .write_all(&greeting)
        .await
        .map_err(|e| Error::Connection(format!("SOCKS5: failed to send greeting: {}", e)))?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.map_err(|e| {
        Error::Connection(format!("SOCKS5: failed to read greeting response: {}", e))
    })?;

    if resp[0] != SOCKS5_VERSION {
        return Err(Error::Connection(format!(
            "SOCKS5: unexpected version 0x{:02x}",
            resp[0]
        )));
    }

    match resp[1] {
        AUTH_NONE => Ok(()),
        AUTH_USER_PASS => {
            let a = auth.ok_or_else(|| {
                Error::Connection("SOCKS5: server requires auth but no credentials provided".into())
            })?;
            authenticate_user_pass(stream, a).await
        }
        AUTH_NO_ACCEPTABLE => Err(Error::Connection(
            "SOCKS5: no acceptable authentication method".into(),
        )),
        method => Err(Error::Connection(format!(
            "SOCKS5: unsupported auth method 0x{:02x}",
            method
        ))),
    }
}

/// Perform RFC 1929 username/password authentication.
async fn authenticate_user_pass(stream: &mut TcpStream, auth: &ProxyAuth) -> Result<(), Error> {
    let uname = auth.username.as_bytes();
    let passwd = auth.password.as_bytes();

    let mut buf = Vec::with_capacity(3 + uname.len() + passwd.len());
    buf.push(USERPASS_VERSION);
    buf.push(uname.len() as u8);
    buf.extend_from_slice(uname);
    buf.push(passwd.len() as u8);
    buf.extend_from_slice(passwd);

    stream
        .write_all(&buf)
        .await
        .map_err(|e| Error::Connection(format!("SOCKS5: failed to send auth: {}", e)))?;

    let mut resp = [0u8; 2];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|e| Error::Connection(format!("SOCKS5: failed to read auth response: {}", e)))?;

    if resp[1] != 0x00 {
        return Err(Error::Connection(
            "SOCKS5: authentication failed (bad username/password)".into(),
        ));
    }

    Ok(())
}

/// Parsed SOCKS5 reply.
struct ReplyInfo {
    reply: u8,
    bound_addr: SocketAddr,
}

/// Read SOCKS5 reply header, consume the bound address, and return the reply code.
/// Discards the bound address (used for CONNECT where we don't need it).
async fn read_reply(stream: &mut TcpStream) -> Result<u8, Error> {
    let info = read_reply_with_addr(stream).await?;
    Ok(info.reply)
}

/// Read full SOCKS5 reply including the bound address.
async fn read_reply_with_addr(stream: &mut TcpStream) -> Result<ReplyInfo, Error> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| Error::Connection(format!("SOCKS5: failed to read reply: {}", e)))?;

    if header[0] != SOCKS5_VERSION {
        return Err(Error::Connection(format!(
            "SOCKS5: unexpected reply version 0x{:02x}",
            header[0]
        )));
    }

    let reply = header[1];
    let atyp = header[3];

    let bound_addr = match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await.map_err(|e| {
                Error::Connection(format!("SOCKS5: failed to read bound IPv4 addr: {}", e))
            })?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await.map_err(|e| {
                Error::Connection(format!("SOCKS5: failed to read bound port: {}", e))
            })?;
            let ip = Ipv4Addr::from(addr);
            let port = u16::from_be_bytes(port_buf);
            SocketAddr::V4(SocketAddrV4::new(ip, port))
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await.map_err(|e| {
                Error::Connection(format!("SOCKS5: failed to read domain length: {}", e))
            })?;
            let dlen = len_buf[0] as usize;
            let mut domain = vec![0u8; dlen];
            stream.read_exact(&mut domain).await.map_err(|e| {
                Error::Connection(format!("SOCKS5: failed to read bound domain: {}", e))
            })?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await.map_err(|e| {
                Error::Connection(format!("SOCKS5: failed to read bound port: {}", e))
            })?;
            let port = u16::from_be_bytes(port_buf);
            // Domain in reply — use unspecified addr with port
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await.map_err(|e| {
                Error::Connection(format!("SOCKS5: failed to read bound IPv6 addr: {}", e))
            })?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await.map_err(|e| {
                Error::Connection(format!("SOCKS5: failed to read bound port: {}", e))
            })?;
            let ip = Ipv6Addr::from(addr);
            let port = u16::from_be_bytes(port_buf);
            SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))
        }
        _ => {
            return Err(Error::Connection(format!(
                "SOCKS5: unsupported address type in reply 0x{:02x}",
                atyp
            )));
        }
    };

    Ok(ReplyInfo { reply, bound_addr })
}

/// Map a SOCKS5 reply code to a human-readable message.
fn reply_message(rep: u8) -> &'static str {
    match rep {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown error",
    }
}
