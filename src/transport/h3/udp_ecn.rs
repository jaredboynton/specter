use std::io;
use std::net::SocketAddr;

use socket2::Socket;
use tokio::net::UdpSocket;

use crate::transport::h3::quic::QuicEcnMark;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UdpDatagramEcn {
    pub len: usize,
    pub peer: SocketAddr,
    pub ecn_mark: Option<QuicEcnMark>,
}

pub(crate) fn enable_udp_ecn_receive(socket: &Socket, local_addr: SocketAddr) -> io::Result<()> {
    if local_addr.is_ipv4() {
        enable_udp_ecn_receive_v4(socket)
    } else {
        enable_udp_ecn_receive_v6(socket)
    }
}

#[cfg(not(any(
    target_os = "aix",
    target_os = "dragonfly",
    target_os = "fuchsia",
    target_os = "hurd",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "redox",
    target_os = "solaris",
    target_os = "haiku",
    target_os = "nto",
    target_os = "espidf",
    target_os = "vita",
    target_os = "cygwin",
)))]
fn enable_udp_ecn_receive_v4(socket: &Socket) -> io::Result<()> {
    socket.set_recv_tos_v4(true)
}

#[cfg(any(
    target_os = "aix",
    target_os = "dragonfly",
    target_os = "fuchsia",
    target_os = "hurd",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "redox",
    target_os = "solaris",
    target_os = "haiku",
    target_os = "nto",
    target_os = "espidf",
    target_os = "vita",
    target_os = "cygwin",
))]
fn enable_udp_ecn_receive_v4(_socket: &Socket) -> io::Result<()> {
    Ok(())
}

#[cfg(not(any(
    target_os = "dragonfly",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "redox",
    target_os = "solaris",
    target_os = "haiku",
    target_os = "hurd",
    target_os = "espidf",
    target_os = "vita",
)))]
fn enable_udp_ecn_receive_v6(socket: &Socket) -> io::Result<()> {
    socket.set_recv_tclass_v6(true)
}

#[cfg(any(
    target_os = "dragonfly",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "redox",
    target_os = "solaris",
    target_os = "haiku",
    target_os = "hurd",
    target_os = "espidf",
    target_os = "vita",
))]
fn enable_udp_ecn_receive_v6(_socket: &Socket) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) async fn recv_from_with_ecn(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<UdpDatagramEcn> {
    use std::os::fd::AsRawFd;

    loop {
        socket.readable().await?;
        match socket.try_io(tokio::io::Interest::READABLE, || {
            recvmsg_with_ecn(socket.as_raw_fd(), buf)
        }) {
            Ok(result) => return Ok(result),
            Err(_would_block) => continue,
        }
    }
}

#[cfg(unix)]
pub(crate) fn try_recv_from_with_ecn(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<Option<UdpDatagramEcn>> {
    use std::os::fd::AsRawFd;

    match socket.try_io(tokio::io::Interest::READABLE, || {
        recvmsg_with_ecn(socket.as_raw_fd(), buf)
    }) {
        Ok(received) => Ok(Some(received)),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(not(unix))]
pub(crate) async fn recv_from_with_ecn(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<UdpDatagramEcn> {
    let (len, peer) = socket.recv_from(buf).await?;
    Ok(UdpDatagramEcn {
        len,
        peer,
        ecn_mark: None,
    })
}

#[cfg(not(unix))]
pub(crate) fn try_recv_from_with_ecn(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<Option<UdpDatagramEcn>> {
    match socket.try_recv_from(buf) {
        Ok((len, peer)) => Ok(Some(UdpDatagramEcn {
            len,
            peer,
            ecn_mark: None,
        })),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn recvmsg_with_ecn(fd: std::os::fd::RawFd, buf: &mut [u8]) -> io::Result<UdpDatagramEcn> {
    use socket2::SockAddr;

    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut control = [0u8; 128];
    let mut ecn_mark = None;

    let (len, peer) = unsafe {
        SockAddr::try_init(|addr_storage, addr_len| {
            let mut message: libc::msghdr = std::mem::zeroed();
            message.msg_name = addr_storage.cast();
            message.msg_namelen = *addr_len;
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = control.len().try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "control buffer too large")
            })?;

            let received = libc::recvmsg(fd, &mut message, 0);
            if received < 0 {
                return Err(io::Error::last_os_error());
            }
            *addr_len = message.msg_namelen;
            ecn_mark = parse_ecn_mark(&message);
            Ok(received as usize)
        })?
    };

    let peer = peer
        .as_socket()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-IP UDP peer address"))?;
    Ok(UdpDatagramEcn {
        len,
        peer,
        ecn_mark,
    })
}

// ===== Batched receive (recvmmsg + per-slot ECN) =====
//
// The single-`recvmsg`-per-wakeup path above drains one datagram per syscall.
// On a multi-datagram response body (the streaming GET fixture emits ~70
// datagrams) that is ~70 syscalls + re-polls, which is the per-datagram cost
// the ledger-paced tail isolates. `UdpRecvBatch` collapses that into one
// `recvmmsg` per wakeup on Linux, preserving per-datagram ECN marks. Non-Linux
// unix targets keep one-datagram-at-a-time semantics so the library still
// builds on macOS dev hosts; the wire bytes are identical either way.

pub(crate) const UDP_RECV_BATCH_SLOTS: usize = 32;
const UDP_RECV_BATCH_SLOT_LEN: usize = 2048;
#[cfg(target_os = "linux")]
const UDP_RECV_BATCH_CONTROL_LEN: usize = 128;

pub(crate) struct UdpRecvBatch {
    bufs: Vec<u8>,
    #[cfg(target_os = "linux")]
    controls: Vec<u8>,
    metas: Vec<UdpDatagramEcn>,
    filled: usize,
}

impl UdpRecvBatch {
    pub(crate) fn new() -> Self {
        let zero_meta = UdpDatagramEcn {
            len: 0,
            peer: SocketAddr::from(([0u8, 0, 0, 0], 0)),
            ecn_mark: None,
        };
        Self {
            bufs: vec![0u8; UDP_RECV_BATCH_SLOTS * UDP_RECV_BATCH_SLOT_LEN],
            #[cfg(target_os = "linux")]
            controls: vec![0u8; UDP_RECV_BATCH_SLOTS * UDP_RECV_BATCH_CONTROL_LEN],
            metas: vec![zero_meta; UDP_RECV_BATCH_SLOTS],
            filled: 0,
        }
    }

    pub(crate) fn meta(&self, index: usize) -> UdpDatagramEcn {
        self.metas[index]
    }

    /// Full slot buffer for `index`; callers slice to `meta(index).len`.
    pub(crate) fn datagram_slot(&self, index: usize) -> &[u8] {
        let start = index * UDP_RECV_BATCH_SLOT_LEN;
        &self.bufs[start..start + UDP_RECV_BATCH_SLOT_LEN]
    }
}

#[cfg(all(unix, target_os = "linux"))]
pub(crate) fn try_recvmmsg_with_ecn(
    socket: &UdpSocket,
    batch: &mut UdpRecvBatch,
    want: usize,
) -> io::Result<usize> {
    use std::os::fd::AsRawFd;

    let want = want.min(UDP_RECV_BATCH_SLOTS);
    if want == 0 {
        batch.filled = 0;
        return Ok(0);
    }
    match socket.try_io(tokio::io::Interest::READABLE, || {
        recvmmsg_with_ecn(socket.as_raw_fd(), batch, want)
    }) {
        Ok(received) => Ok(received),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            batch.filled = 0;
            Ok(0)
        }
        Err(error) => Err(error),
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn try_recvmmsg_with_ecn(
    socket: &UdpSocket,
    batch: &mut UdpRecvBatch,
    want: usize,
) -> io::Result<usize> {
    let want = want.min(UDP_RECV_BATCH_SLOTS);
    let mut received = 0;
    while received < want {
        let start = received * UDP_RECV_BATCH_SLOT_LEN;
        let datagram = {
            let slot = &mut batch.bufs[start..start + UDP_RECV_BATCH_SLOT_LEN];
            try_recv_from_with_ecn(socket, slot)?
        };
        match datagram {
            Some(meta) => {
                batch.metas[received] = meta;
                received += 1;
            }
            None => break,
        }
    }
    batch.filled = received;
    Ok(received)
}

#[cfg(not(unix))]
pub(crate) fn try_recvmmsg_with_ecn(
    socket: &UdpSocket,
    batch: &mut UdpRecvBatch,
    want: usize,
) -> io::Result<usize> {
    let want = want.min(UDP_RECV_BATCH_SLOTS);
    let mut received = 0;
    while received < want {
        let start = received * UDP_RECV_BATCH_SLOT_LEN;
        let datagram = {
            let slot = &mut batch.bufs[start..start + UDP_RECV_BATCH_SLOT_LEN];
            try_recv_from_with_ecn(socket, slot)?
        };
        match datagram {
            Some(meta) => {
                batch.metas[received] = meta;
                received += 1;
            }
            None => break,
        }
    }
    batch.filled = received;
    Ok(received)
}

#[cfg(target_os = "linux")]
fn recvmmsg_with_ecn(
    fd: std::os::fd::RawFd,
    batch: &mut UdpRecvBatch,
    want: usize,
) -> io::Result<usize> {
    let want = want.min(UDP_RECV_BATCH_SLOTS);
    let mut names: [libc::sockaddr_storage; UDP_RECV_BATCH_SLOTS] = unsafe { std::mem::zeroed() };
    let mut iovecs: [libc::iovec; UDP_RECV_BATCH_SLOTS] = unsafe { std::mem::zeroed() };
    let mut msgs: [libc::mmsghdr; UDP_RECV_BATCH_SLOTS] = unsafe { std::mem::zeroed() };

    let bufs_ptr = batch.bufs.as_mut_ptr();
    let controls_ptr = batch.controls.as_mut_ptr();
    for index in 0..want {
        iovecs[index].iov_base = unsafe { bufs_ptr.add(index * UDP_RECV_BATCH_SLOT_LEN) }.cast();
        iovecs[index].iov_len = UDP_RECV_BATCH_SLOT_LEN;
        let header = &mut msgs[index].msg_hdr;
        header.msg_name = (&mut names[index] as *mut libc::sockaddr_storage).cast();
        header.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        header.msg_iov = &mut iovecs[index] as *mut libc::iovec;
        header.msg_iovlen = 1;
        header.msg_control = unsafe { controls_ptr.add(index * UDP_RECV_BATCH_CONTROL_LEN) }.cast();
        header.msg_controllen = UDP_RECV_BATCH_CONTROL_LEN;
        header.msg_flags = 0;
        msgs[index].msg_len = 0;
    }

    let received = unsafe {
        libc::recvmmsg(
            fd,
            msgs.as_mut_ptr(),
            want as libc::c_uint,
            libc::MSG_DONTWAIT,
            std::ptr::null_mut(),
        )
    };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let received = received as usize;
    for index in 0..received {
        let len = (msgs[index].msg_len as usize).min(UDP_RECV_BATCH_SLOT_LEN);
        let peer = sockaddr_storage_to_socket(&names[index], msgs[index].msg_hdr.msg_namelen)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-IP UDP peer address"))?;
        let ecn_mark = parse_ecn_mark(&msgs[index].msg_hdr);
        batch.metas[index] = UdpDatagramEcn {
            len,
            peer,
            ecn_mark,
        };
    }
    batch.filled = received;
    Ok(received)
}

#[cfg(target_os = "linux")]
fn sockaddr_storage_to_socket(
    storage: &libc::sockaddr_storage,
    _len: libc::socklen_t,
) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let addr =
                unsafe { &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            Some(SocketAddr::new(
                std::net::IpAddr::V4(ip),
                u16::from_be(addr.sin_port),
            ))
        }
        libc::AF_INET6 => {
            let addr = unsafe {
                &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in6)
            };
            let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
            Some(SocketAddr::new(
                std::net::IpAddr::V6(ip),
                u16::from_be(addr.sin6_port),
            ))
        }
        _ => None,
    }
}

#[cfg(unix)]
fn parse_ecn_mark(message: &libc::msghdr) -> Option<QuicEcnMark> {
    unsafe {
        let mut control = libc::CMSG_FIRSTHDR(message);
        while !control.is_null() {
            let header = std::ptr::read_unaligned(control);
            if header.cmsg_level == libc::IPPROTO_IP && header.cmsg_type == libc::IP_TOS {
                let tos = *(libc::CMSG_DATA(control).cast::<u8>());
                if let Some(mark) = QuicEcnMark::from_ip_tos_bits(tos) {
                    return Some(mark);
                }
            }
            if header.cmsg_level == libc::IPPROTO_IPV6 && header.cmsg_type == libc::IPV6_TCLASS {
                let traffic_class =
                    std::ptr::read_unaligned(libc::CMSG_DATA(control).cast::<libc::c_int>());
                if let Some(mark) = QuicEcnMark::from_ip_tos_bits(traffic_class as u8) {
                    return Some(mark);
                }
            }
            control =
                libc::CMSG_NXTHDR(message as *const libc::msghdr as *mut libc::msghdr, control);
        }
    }
    None
}
