//! Browser header presets for HTTP requests.
//!
//! WARNING: These headers are for Chrome 131 which is outdated.
//! Chrome 142 is current as of December 2025. The Sec-Ch-Ua values
//! and User-Agent strings should be updated for production use.

use crate::cookie::CookieJar;

/// Chrome 131 browser headers for page navigation.
pub fn chrome_131_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        ("Sec-Ch-Ua", r#""Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24""#),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 131 headers for AJAX/API requests.
pub fn chrome_131_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        ("Sec-Ch-Ua", r#""Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24""#),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 131 headers for form submissions.
pub fn chrome_131_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        ("Sec-Ch-Ua", r#""Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24""#),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Add Cookie header from jar.
pub fn with_cookies(base: Vec<(&'static str, &'static str)>, url: &str, jar: &CookieJar) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = base.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
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
    headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

/// Convert static headers to owned.
pub fn headers_to_owned(headers: Vec<(&'static str, &'static str)>) -> Vec<(String, String)> {
    headers.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}
