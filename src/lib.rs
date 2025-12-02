//! # Specter
//!
//! HTTP client with full TLS/HTTP2 fingerprint control.
//!
//! Specter provides HTTP/1.1, HTTP/2, and HTTP/3 support with BoringSSL-based
//! TLS fingerprinting (JA3/JA4) across all protocols.

// Core modules (to be ported from curl-http)
pub mod cookie;
pub mod error;
pub mod headers;
pub mod response;
pub mod version;

// Fingerprinting (to be implemented)
pub mod fingerprint;

// Transport layer (to be implemented)
pub mod transport;

// Connection pooling (to be implemented)
pub mod pool;

// Re-exports
pub use cookie::CookieJar;
pub use error::{Error, Result};
pub use version::HttpVersion;
