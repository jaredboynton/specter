//! # Specter
//!
//! HTTP client with full TLS/HTTP2 fingerprint control.
//!
//! Specter provides HTTP/1.1, HTTP/2, and HTTP/3 support with BoringSSL-based
//! TLS fingerprinting (JA3/JA4) across all protocols.

// Core modules
pub mod cookie;
pub mod error;
pub mod headers;
pub mod response;
pub mod version;

// Fingerprinting
pub mod fingerprint;

// Transport layer
pub mod transport;

// Connection pooling
pub mod pool;

// Re-exports for convenient access
pub use cookie::{hash_cookie_value, CookieJar};
pub use error::{Error, Result};
pub use fingerprint::FingerprintProfile;
pub use response::Response;
pub use version::HttpVersion;

// Transport re-exports
pub use transport::connector::{AlpnProtocol, BoringConnector, MaybeHttpsStream};
pub use transport::h1::H1Connection;
pub use transport::h1_h2::{Client, ClientBuilder, RequestBuilder};
pub use transport::h2::{H2ClientBuilder, H2Connection, H2PooledConnection, PseudoHeaderOrder};
pub use transport::h3::H3Client;

// Pool re-exports
pub use pool::alt_svc::{AltSvcCache, AltSvcEntry};
pub use pool::multiplexer::{ConnectionPool, PoolEntry, PoolKey};
