//! TCP/IP stack fingerprinting for browser impersonation.
//!
//! Configures TCP socket options to match browser behavior:
//! - Initial window size
//! - TTL (Time To Live)
//! - MSS (Maximum Segment Size)
//! - Window scaling
//! - SACK (Selective Acknowledgment)
//! - TCP timestamps
//!
//! These options are detectable before TLS handshake (p0f-style fingerprinting).

use std::io;

/// TCP/IP fingerprint configuration.
#[derive(Debug, Clone)]
pub struct TcpFingerprint {
    /// Initial receive window size (bytes).
    /// Chrome: 65535 (default), can be adjusted via socket buffer size
    pub window_size: u32,
    /// Initial TTL (Time To Live) for IPv4 packets.
    /// macOS: 64, Linux: 64, Windows: 128
    pub ttl: u8,
    /// Maximum Segment Size (MSS).
    /// Typically 1460 for Ethernet (1500 MTU - 40 IP/TCP headers)
    pub mss: u16,
    /// Window scaling factor (RFC 1323).
    /// Chrome: typically 6-7 (64KB * 2^6 = 4MB window)
    pub window_scale: u8,
    /// Enable SACK (Selective Acknowledgment).
    /// Modern browsers: true
    pub sack_permitted: bool,
    /// Enable TCP timestamps (RFC 1323).
    /// Modern browsers: true
    pub timestamps: bool,
}

impl Default for TcpFingerprint {
    fn default() -> Self {
        // Chrome defaults on macOS
        Self {
            window_size: 65535,
            ttl: 64,   // macOS default
            mss: 1460, // Ethernet MTU - headers
            window_scale: 6,
            sack_permitted: true,
            timestamps: true,
        }
    }
}

impl TcpFingerprint {
    /// Create Chrome TCP fingerprint.
    pub fn chrome() -> Self {
        Self::default()
    }

    /// Create Firefox TCP fingerprint.
    /// Firefox uses similar TCP settings to Chrome.
    pub fn firefox() -> Self {
        Self::default()
    }
}

/// Configure a TCP socket with fingerprint settings.
///
/// Uses socket2 crate for cross-platform socket options.
/// Some TCP options may not be available or configurable on all platforms.
pub fn configure_tcp_socket(socket: &socket2::Socket, fp: &TcpFingerprint) -> io::Result<()> {
    // Set receive buffer size (influences window size)
    socket.set_recv_buffer_size(fp.window_size as usize)?;

    // Set send buffer size (should match receive for symmetry)
    socket.set_send_buffer_size(fp.window_size as usize)?;

    // Set TTL for IPv4 packets
    socket.set_ttl_v4(fp.ttl as u32)?;

    // MSS (Maximum Segment Size) is negotiated during TCP handshake and cannot be
    // directly set via socket options. The OS handles MSS negotiation based
    // on MTU discovery.

    // Window scaling, SACK, and timestamps are negotiated during TCP handshake
    // via TCP options. These are typically handled by the OS TCP stack and
    // cannot be directly controlled via socket2 on all platforms.
    //
    // For full control, we would need raw sockets or platform-specific APIs.
    // This implementation focuses on what can be reliably configured via
    // standard socket options.

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_fingerprint_defaults() {
        let fp = TcpFingerprint::default();
        assert_eq!(fp.window_size, 65535);
        assert_eq!(fp.ttl, 64);
        assert_eq!(fp.mss, 1460);
        assert_eq!(fp.window_scale, 6);
        assert!(fp.sack_permitted);
        assert!(fp.timestamps);
    }

    #[test]
    fn test_chrome_firefox_similar() {
        let chrome = TcpFingerprint::chrome();
        let firefox = TcpFingerprint::firefox();
        // Chrome and Firefox use similar TCP settings
        assert_eq!(chrome.window_size, firefox.window_size);
        assert_eq!(chrome.ttl, firefox.ttl);
    }
}
