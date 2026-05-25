//! TCP/IP fingerprinting example.
//!
//! Demonstrates how to configure TCP socket options for browser impersonation.
//!
//! Run with: cargo run --example tcp_fingerprint
//!
//! TCP fingerprinting configures metadata and portable options such as:
//! - Initial window size metadata
//! - TTL (Time To Live)
//! - Optional TCP_NOTSENT_LOWAT
//!
//! Socket buffer sizes are OS-autotuned by default. Use `TcpSocketBuffers`
//! only when a deployment explicitly needs fixed `SO_RCVBUF` / `SO_SNDBUF`.
//!
//! Note: Some TCP options (MSS, window scaling, SACK, timestamps) are negotiated
//! during TCP handshake and cannot be directly set via socket2 on all platforms.

use specter::fingerprint::tls::TlsFingerprint;
use specter::transport::connector::BoringConnector;
use specter::transport::tcp::{TcpFingerprint, TcpSocketBuffers};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("=== TCP Fingerprinting Example ===");
    info!("");

    // Create TCP fingerprint (Chrome defaults)
    let tcp_fp = TcpFingerprint::chrome();
    info!("TCP Fingerprint Configuration:");
    info!("  - Window Size: {} bytes", tcp_fp.window_size);
    info!("  - TTL: {}", tcp_fp.ttl);
    info!("  - MSS: {} bytes", tcp_fp.mss);
    info!("  - Window Scale: {}", tcp_fp.window_scale);
    info!("  - SACK Permitted: {}", tcp_fp.sack_permitted);
    info!("  - Timestamps: {}", tcp_fp.timestamps);
    info!("  - Socket Buffers: OS autotuned by default");
    info!("");

    // Create TLS fingerprint
    let tls_fp = TlsFingerprint::chrome_142();

    // Create connector with both TLS and TCP fingerprints
    let connector = BoringConnector::with_fingerprints(tls_fp, tcp_fp.clone());

    info!("Connecting to example.com with TCP fingerprinting...");
    let uri: http::Uri = "https://example.com".parse()?;

    match connector.connect(&uri).await {
        Ok(stream) => {
            info!("[SUCCESS] Connection established with TCP fingerprint");

            // Verify connection properties
            if let specter::transport::connector::MaybeHttpsStream::Https(ssl_stream) = &stream {
                info!("  - TLS Version: {:?}", ssl_stream.ssl().version_str());
                if let Some(cipher) = ssl_stream.ssl().current_cipher() {
                    info!("  - Cipher: {}", cipher.name());
                }
            }

            info!("  - ALPN: {:?}", stream.alpn_protocol());
            info!("  - HTTP/2: {}", stream.is_h2());
        }
        Err(e) => {
            tracing::error!("Connection failed: {}", e);
            return Err(e.into());
        }
    }

    info!("");

    // Demonstrate Firefox TCP fingerprint (similar to Chrome)
    let firefox_tcp_fp = TcpFingerprint::firefox();
    info!("Firefox TCP Fingerprint:");
    info!("  - Window Size: {} bytes", firefox_tcp_fp.window_size);
    info!("  - TTL: {}", firefox_tcp_fp.ttl);
    info!("  - Note: Firefox uses similar TCP settings to Chrome");
    info!("");

    // Demonstrate custom TCP fingerprint
    let custom_tcp_fp = TcpFingerprint {
        window_size: 131072, // 128KB
        ttl: 64,
        mss: 1460,
        window_scale: 7,
        sack_permitted: true,
        timestamps: true,
        tcp_notsent_lowat: None,
    };

    info!("Custom TCP Fingerprint:");
    info!(
        "  - Window Size: {} bytes (custom)",
        custom_tcp_fp.window_size
    );
    info!("  - Window Scale: {} (custom)", custom_tcp_fp.window_scale);
    info!("");

    let fixed_buffer_connector = BoringConnector::new()
        .with_tcp_fingerprint(custom_tcp_fp)
        .tcp_socket_buffers(TcpSocketBuffers::symmetric(262_144));
    drop(fixed_buffer_connector);
    info!("Explicit socket buffers can be opted into with TcpSocketBuffers");
    info!("");

    info!("TCP fingerprinting helps match browser TCP/IP stack characteristics");
    info!("before the TLS handshake, making detection more difficult.");

    Ok(())
}
