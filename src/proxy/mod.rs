//! Proxy support for SOCKS5 and HTTP CONNECT tunneling.

pub mod http_connect;
pub mod socks5;
pub mod udp_transport;

/// Authentication credentials for proxy connections.
#[derive(Debug, Clone)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

/// Proxy configuration for tunneling connections.
#[derive(Debug, Clone)]
pub enum ProxyConfig {
    /// SOCKS5 proxy (RFC 1928).
    Socks5 {
        host: String,
        port: u16,
        auth: Option<ProxyAuth>,
    },
    /// HTTP CONNECT proxy.
    HttpConnect {
        host: String,
        port: u16,
        auth: Option<ProxyAuth>,
    },
}

impl ProxyConfig {
    /// Create a SOCKS5 proxy config without authentication.
    pub fn socks5(host: impl Into<String>, port: u16) -> Self {
        Self::Socks5 {
            host: host.into(),
            port,
            auth: None,
        }
    }

    /// Create a SOCKS5 proxy config with username/password authentication.
    pub fn socks5_with_auth(
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self::Socks5 {
            host: host.into(),
            port,
            auth: Some(ProxyAuth {
                username: username.into(),
                password: password.into(),
            }),
        }
    }

    /// Create an HTTP CONNECT proxy config without authentication.
    pub fn http_connect(host: impl Into<String>, port: u16) -> Self {
        Self::HttpConnect {
            host: host.into(),
            port,
            auth: None,
        }
    }

    /// Create an HTTP CONNECT proxy config with username/password authentication.
    pub fn http_connect_with_auth(
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self::HttpConnect {
            host: host.into(),
            port,
            auth: Some(ProxyAuth {
                username: username.into(),
                password: password.into(),
            }),
        }
    }

    /// Returns the proxy (host, port) regardless of variant.
    pub fn addr(&self) -> (&str, u16) {
        match self {
            Self::Socks5 { host, port, .. } => (host, *port),
            Self::HttpConnect { host, port, .. } => (host, *port),
        }
    }

    /// Returns a unique string key for connection pool keying.
    pub fn proxy_key(&self) -> String {
        match self {
            Self::Socks5 { host, port, .. } => format!("socks5://{}:{}", host, port),
            Self::HttpConnect { host, port, .. } => format!("http-connect://{}:{}", host, port),
        }
    }
}
