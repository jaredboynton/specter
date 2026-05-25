//! C1 integration test: TLS 1.3 session ticket resumption across back-to-back dials.
//!
//! Spins a local BoringSSL accept loop on `127.0.0.1:0`, performs two `connect()`
//! calls through a shared `BoringConnector`, and asserts the second handshake
//! resumed via the cached session ticket.

mod helpers;

use boring::ssl::{SslOptions, SslSessionCacheMode, SslVersion};
use helpers::tls::generate_cert_bundle;
use specter::transport::connector::BoringConnector;
use specter::transport::dns::{DnsConfig, Resolve, ResolveFuture};
use specter::transport::session::SessionCache;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

struct StaticResolver {
    addrs: Vec<SocketAddr>,
}

impl Resolve for StaticResolver {
    fn resolve<'a>(&'a self, _host: &'a str, _port: u16) -> ResolveFuture<'a> {
        let addrs = self.addrs.clone();
        Box::pin(async move { Ok(addrs) })
    }
}

/// Spawn a minimal TLS 1.3 accept loop that issues a fresh session ticket and
/// writes a single `PING` byte string after the handshake completes so that the
/// client surfaces the NewSessionTicket via its `set_new_session_callback`.
async fn spawn_tls13_ticket_server() -> (SocketAddr, Vec<u8>, oneshot::Sender<()>) {
    let (mut builder, ca_pem) = generate_cert_bundle();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .expect("min version");
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .expect("max version");
    builder.set_session_cache_mode(SslSessionCacheMode::SERVER);
    // BoringSSL issues TLS 1.3 NewSessionTicket automatically after the handshake;
    // ensure stateful tickets are not disabled.
    builder.clear_options(SslOptions::NO_TICKET);
    let acceptor = Arc::new(builder.build());

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accept = listener.accept() => {
                    let Ok((tcp, _)) = accept else { break };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(mut tls) = tokio_boring::accept(&acceptor, tcp).await else { return };
                        // Send a small payload so the client's read drives ticket processing.
                        let _ = tls.write_all(b"PING\n").await;
                        let _ = tls.flush().await;
                        let mut buf = [0u8; 16];
                        let _ = tls.read(&mut buf).await;
                        let _ = tls.shutdown().await;
                    });
                }
            }
        }
    });

    (addr, ca_pem, shutdown_tx)
}

#[tokio::test]
async fn second_connect_resumes_tls13_session_ticket() {
    let (addr, ca_pem, shutdown) = spawn_tls13_ticket_server().await;
    let shared_cache = Arc::new(SessionCache::new());
    let resolver = Arc::new(StaticResolver {
        addrs: vec![addr],
    });
    let connector = BoringConnector::new()
        .with_root_certificates(vec![ca_pem])
        .with_shared_session_cache(shared_cache.clone())
        .with_dns_config(
            DnsConfig::new()
                .with_resolver(resolver)
                .with_cache_enabled(false),
        );

    // Use a stable SNI hostname (must match the loopback cert SANs).
    let uri: http::Uri = format!("https://127.0.0.1:{}/", addr.port())
        .parse()
        .unwrap();

    let mut first = connector
        .connect(&uri)
        .await
        .expect("first TLS handshake");
    assert!(
        !first.session_reused(),
        "first handshake should be a fresh session, not resumption"
    );
    // Drive a read so the client processes the NewSessionTicket frame.
    let mut buf = [0u8; 8];
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        use tokio::io::AsyncReadExt;
        first.read(&mut buf).await
    })
    .await;
    drop(first);

    // Poll the cache briefly: the new-session callback runs after BoringSSL parses
    // the NewSessionTicket, which can land slightly after the read returns bytes.
    let key = specter::transport::session::SessionCacheKey::new("127.0.0.1", addr.port());
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while shared_cache.get_session(&key).is_none() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        shared_cache.get_session(&key).is_some(),
        "expected a TLS 1.3 session ticket to be cached after the first dial"
    );

    let second = connector.connect(&uri).await.expect("second TLS handshake");
    assert!(
        second.session_reused(),
        "second handshake must resume the cached TLS 1.3 ticket"
    );

    let _ = shutdown.send(());
}
