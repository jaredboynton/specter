//! Browser header presets for HTTP requests.
//!
//! Current implementation: Chrome 142 (Dec 2025)

use crate::cookie::CookieJar;

/// Chrome 142 browser headers for page navigation.
pub fn chrome_142_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        ("Sec-Ch-Ua", r#""Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="24""#),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 142 headers for AJAX/API requests.
pub fn chrome_142_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        ("Sec-Ch-Ua", r#""Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="24""#),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 142 headers for form submissions.
pub fn chrome_142_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        ("Sec-Ch-Ua", r#""Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="24""#),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Add Cookie header from jar.
pub fn with_cookies(
    base: Vec<(&'static str, &'static str)>,
    url: &str,
    jar: &CookieJar,
) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = base
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    if let Some(cookie_header) = jar.build_cookie_header(url) {
        headers.push(("Cookie".to_string(), cookie_header));
    }
    headers
}

/// Add Origin header.
pub fn with_origin(mut headers: Vec<(String, String)>, origin: &str) -> Vec<(String, String)> {
    headers.retain(|(k, _)| k.to_lowercase() != "origin");
    headers.push(("Origin".to_string(), origin.to_string()));
    headers
}

/// Add Referer header.
pub fn with_referer(mut headers: Vec<(String, String)>, referer: &str) -> Vec<(String, String)> {
    headers.retain(|(k, _)| k.to_lowercase() != "referer");
    headers.push(("Referer".to_string(), referer.to_string()));
    headers
}

/// Convert owned headers to references.
pub fn headers_as_refs(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

/// Convert static headers to owned.
pub fn headers_to_owned(headers: Vec<(&'static str, &'static str)>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Ordered headers with JA4H fingerprint calculation.
///
/// JA4H (JA4 for HTTP) fingerprints HTTP clients based on:
/// - Header order
/// - Header names (normalized to lowercase)
/// - Header values (normalized)
///
/// This type preserves exact header order for fingerprint accuracy.
#[derive(Debug, Clone)]
pub struct OrderedHeaders {
    headers: Vec<(String, String)>,
}

impl OrderedHeaders {
    /// Create new ordered headers.
    pub fn new(headers: Vec<(String, String)>) -> Self {
        Self { headers }
    }

    /// Create Chrome navigation headers with exact order.
    pub fn chrome_navigation() -> Self {
        Self::new(headers_to_owned(chrome_142_headers()))
    }

    /// Create Firefox navigation headers with exact order.
    pub fn firefox_navigation() -> Self {
        Self::new(headers_to_owned(firefox_133_headers()))
    }

    /// Get headers as vector.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Calculate JA4H fingerprint string.
    ///
    /// JA4H format: header_names|header_order_hash
    /// - header_names: comma-separated lowercase header names
    /// - header_order_hash: hash of header order
    pub fn ja4h_fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};

        // Extract header names (lowercase) in order
        let header_names: Vec<String> = self
            .headers
            .iter()
            .map(|(name, _)| name.to_lowercase())
            .collect();

        // Create header names string
        let names_str = header_names.join(",");

        // Calculate hash of header order (using names for simplicity)
        let mut hasher = Sha256::new();
        hasher.update(names_str.as_bytes());
        let hash = hasher.finalize();

        // Use first 12 hex characters (24 bits) for fingerprint
        let hash_str: String = hash[..3].iter().map(|b| format!("{:02x}", b)).collect();

        format!("{}|{}", names_str, hash_str)
    }

    /// Add a header (preserves order).
    pub fn add(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Convert to vector of owned headers.
    pub fn into_vec(self) -> Vec<(String, String)> {
        self.headers
    }
}

impl From<Vec<(String, String)>> for OrderedHeaders {
    fn from(headers: Vec<(String, String)>) -> Self {
        Self::new(headers)
    }
}

impl From<OrderedHeaders> for Vec<(String, String)> {
    fn from(oh: OrderedHeaders) -> Self {
        oh.headers
    }
}

/// Firefox 133 browser headers for page navigation.
/// Firefox does NOT send Sec-Ch-Ua headers (Client Hints).
pub fn firefox_133_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.5"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Firefox 133 headers for AJAX/API requests.
pub fn firefox_133_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
        ),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.5"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        ("Connection", "keep-alive"),
    ]
}

/// Firefox 133 headers for form submissions.
pub fn firefox_133_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.5"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}
