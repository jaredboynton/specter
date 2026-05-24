//! Browser header presets for HTTP requests.
//!
//! Supported Chrome versions: 142, 143, 144, 145, 146, 147, 148
//! Supported Firefox versions: 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, ESR 115, ESR 128, ESR 140

use crate::cookie::CookieJar;
use http::HeaderMap;

/// Chrome 142 browser headers for page navigation.
pub fn chrome_142_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Chromium";v="142.0.7444.176", "Google Chrome";v="142.0.7444.176", "Not_A Brand";v="99.0.0.0""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 142 headers for AJAX/API requests.
/// Extended Client Hints are typically only sent on navigation requests,
/// not on AJAX/API requests unless explicitly requested by the server.
pub fn chrome_142_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        ),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 142 headers for form submissions.
pub fn chrome_142_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Chromium";v="142.0.7444.176", "Google Chrome";v="142.0.7444.176", "Not_A Brand";v="99.0.0.0""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 143 browser headers for page navigation.
pub fn chrome_143_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        (
            "Sec-Ch-Ua",
            r#""Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Google Chrome";v="143.0.7499.193", "Chromium";v="143.0.7499.193", "Not A(Brand";v="24.0.0.0""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 143 headers for AJAX/API requests.
pub fn chrome_143_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
        ),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 143 headers for form submissions.
pub fn chrome_143_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Google Chrome";v="143.0.7499.193", "Chromium";v="143.0.7499.193", "Not A(Brand";v="24.0.0.0""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 144 browser headers for page navigation.
pub fn chrome_144_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        (
            "Sec-Ch-Ua",
            r#""Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Not(A:Brand";v="8.0.0.0", "Chromium";v="144.0.7559.133", "Google Chrome";v="144.0.7559.133""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 144 headers for AJAX/API requests.
pub fn chrome_144_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        ),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 144 headers for form submissions.
pub fn chrome_144_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Not(A:Brand";v="8.0.0.0", "Chromium";v="144.0.7559.133", "Google Chrome";v="144.0.7559.133""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 145 browser headers for page navigation.
pub fn chrome_145_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        (
            "Sec-Ch-Ua",
            r#""Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Not:A-Brand";v="99.0.0.0", "Google Chrome";v="145.0.7632.117", "Chromium";v="145.0.7632.117""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 145 headers for AJAX/API requests.
pub fn chrome_145_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        ),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 145 headers for form submissions.
pub fn chrome_145_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Not:A-Brand";v="99.0.0.0", "Google Chrome";v="145.0.7632.117", "Chromium";v="145.0.7632.117""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 146 browser headers for page navigation.
pub fn chrome_146_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Chromium";v="146.0.7680.165", "Not-A.Brand";v="24.0.0.0", "Google Chrome";v="146.0.7680.165""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 146 headers for AJAX/API requests.
pub fn chrome_146_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        ),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 146 headers for form submissions.
pub fn chrome_146_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Chromium";v="146.0.7680.165", "Not-A.Brand";v="24.0.0.0", "Google Chrome";v="146.0.7680.165""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 147 browser headers for page navigation.
pub fn chrome_147_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        (
            "Sec-Ch-Ua",
            r#""Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Google Chrome";v="147.0.7727.138", "Not.A/Brand";v="8.0.0.0", "Chromium";v="147.0.7727.138""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 147 headers for AJAX/API requests.
pub fn chrome_147_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        ),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 147 headers for form submissions.
pub fn chrome_147_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Google Chrome";v="147.0.7727.138", "Not.A/Brand";v="8.0.0.0", "Chromium";v="147.0.7727.138""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 148 browser headers for page navigation.
pub fn chrome_148_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Chromium";v="148.0.7778.179", "Google Chrome";v="148.0.7778.179", "Not/A)Brand";v="99.0.0.0""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 148 headers for AJAX/API requests.
pub fn chrome_148_ajax_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        ),
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/json"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "cors"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Connection", "keep-alive"),
    ]
}

/// Chrome 148 headers for form submissions.
pub fn chrome_148_form_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        ),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br, zstd"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "same-origin"),
        (
            "Sec-Ch-Ua",
            r#""Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99""#,
        ),
        ("Sec-Ch-Ua-Mobile", "?0"),
        ("Sec-Ch-Ua-Platform", r#""macOS""#),
        ("Sec-Ch-Ua-Arch", r#""arm64""#),
        ("Sec-Ch-Ua-Bitness", r#""64""#),
        (
            "Sec-Ch-Ua-Full-Version-List",
            r#""Chromium";v="148.0.7778.179", "Google Chrome";v="148.0.7778.179", "Not/A)Brand";v="99.0.0.0""#,
        ),
        ("Sec-Ch-Ua-Model", r#""""#),
        ("Sec-Ch-Ua-Platform-Version", r#""15.5.0""#),
        ("Sec-Ch-Ua-Wow64", "?0"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Connection", "keep-alive"),
    ]
}

/// Add Cookie header from jar.
pub fn with_cookies(base: impl Into<Headers>, url: &str, jar: &CookieJar) -> Headers {
    let mut headers: Headers = base.into();
    headers.remove("cookie");
    if let Some(cookie_header) = jar.build_cookie_header(url) {
        headers.append("Cookie", cookie_header);
    }
    headers
}

/// Add Origin header.
pub fn with_origin(mut headers: Headers, origin: &str) -> Headers {
    headers.remove("origin");
    headers.append("Origin", origin.to_string());
    headers
}

/// Add Referer header.
pub fn with_referer(mut headers: Headers, referer: &str) -> Headers {
    headers.remove("referer");
    headers.append("Referer", referer.to_string());
    headers
}

/// Convert owned headers to references.
pub fn headers_as_refs(headers: &Headers) -> Vec<(&str, &str)> {
    headers.as_refs()
}

/// Convert static headers to owned.
pub fn headers_to_owned(headers: Vec<(&'static str, &'static str)>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Ordered headers for requests and responses.
///
/// This preserves insertion order for fingerprinting while providing
/// convenient lookup and mutation helpers.
#[derive(Debug, Clone, Default)]
pub struct Headers {
    headers: Vec<(String, String)>,
}

impl Headers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_vec(headers: Vec<(String, String)>) -> Self {
        Self { headers }
    }

    pub fn from_static(headers: Vec<(&'static str, &'static str)>) -> Self {
        Self {
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.headers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(&name));
        self.headers.push((name, value.into()));
    }

    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.push((name.into(), value.into()));
    }

    pub fn remove(&mut self, name: &str) -> Option<Vec<String>> {
        let mut removed = Vec::new();
        self.headers.retain(|(k, v)| {
            if k.eq_ignore_ascii_case(name) {
                removed.push(v.clone());
                false
            } else {
                true
            }
        });
        if removed.is_empty() {
            None
        } else {
            Some(removed)
        }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|(k, v)| {
            if k.eq_ignore_ascii_case(name) {
                Some(v.as_str())
            } else {
                None
            }
        })
    }

    pub fn get_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter_map(|(k, v)| {
                if k.eq_ignore_ascii_case(name) {
                    Some(v.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn iter_ordered(&self) -> impl Iterator<Item = (&str, &str)> {
        self.iter()
    }

    pub fn extend(&mut self, other: Headers) {
        self.headers.extend(other.headers);
    }

    pub fn as_slice(&self) -> &[(String, String)] {
        &self.headers
    }

    pub fn as_refs(&self) -> Vec<(&str, &str)> {
        self.headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    pub fn to_vec(&self) -> Vec<(String, String)> {
        self.headers.clone()
    }

    pub fn into_inner(self) -> Vec<(String, String)> {
        self.headers
    }
}

impl From<Vec<(String, String)>> for Headers {
    fn from(value: Vec<(String, String)>) -> Self {
        Headers::from_vec(value)
    }
}

impl From<Vec<(&'static str, &'static str)>> for Headers {
    fn from(value: Vec<(&'static str, &'static str)>) -> Self {
        Headers::from_static(value)
    }
}

impl From<HeaderMap> for Headers {
    fn from(map: HeaderMap) -> Self {
        let mut headers = Vec::new();
        for (name, value) in map.iter() {
            let value = value
                .to_str()
                .map(|s| s.to_string())
                .unwrap_or_else(|_| String::from_utf8_lossy(value.as_bytes()).into_owned());
            headers.push((name.as_str().to_string(), value));
        }
        Headers { headers }
    }
}

/// Ordered headers with JA4H fingerprint calculation.
///
/// JA4H (JA4 for HTTP) fingerprints HTTP clients based on:
/// - Header order
/// - Header names (normalized to lowercase)
///
/// This implementation is intentionally header-name/order based and does not
/// include header values in the hash. Firefox version differences that only
/// change the User-Agent value are not JA4H-distinguishable here.
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
    /// Uses Chrome 148 (latest implemented) by default.
    pub fn chrome_navigation() -> Self {
        Self::new(headers_to_owned(chrome_148_headers()))
    }

    /// Create Firefox navigation headers with exact order.
    /// Uses Firefox 151 (latest implemented release) by default.
    pub fn firefox_navigation() -> Self {
        Self::new(headers_to_owned(firefox_151_headers()))
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

fn firefox_navigation_headers(ua: &'static str) -> Vec<(&'static str, &'static str)> {
    vec![
        ("User-Agent", ua),
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

fn firefox_ajax_headers(ua: &'static str) -> Vec<(&'static str, &'static str)> {
    vec![
        ("User-Agent", ua),
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

fn firefox_form_headers(ua: &'static str) -> Vec<(&'static str, &'static str)> {
    vec![
        ("User-Agent", ua),
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

macro_rules! firefox_header_set {
    ($headers_fn:ident, $ajax_fn:ident, $form_fn:ident, $ua:literal, $label:literal) => {
        #[doc = concat!("Firefox ", $label, " browser headers for page navigation.")]
        #[doc = "Firefox does NOT send Sec-Ch-Ua headers (Client Hints)."]
        pub fn $headers_fn() -> Vec<(&'static str, &'static str)> {
            firefox_navigation_headers($ua)
        }

        #[doc = concat!("Firefox ", $label, " headers for AJAX/API requests.")]
        pub fn $ajax_fn() -> Vec<(&'static str, &'static str)> {
            firefox_ajax_headers($ua)
        }

        #[doc = concat!("Firefox ", $label, " headers for form submissions.")]
        pub fn $form_fn() -> Vec<(&'static str, &'static str)> {
            firefox_form_headers($ua)
        }
    };
}

firefox_header_set!(
    firefox_133_headers,
    firefox_133_ajax_headers,
    firefox_133_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "133"
);
firefox_header_set!(
    firefox_134_headers,
    firefox_134_ajax_headers,
    firefox_134_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:134.0) Gecko/20100101 Firefox/134.0",
    "134"
);
firefox_header_set!(
    firefox_135_headers,
    firefox_135_ajax_headers,
    firefox_135_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
    "135"
);
firefox_header_set!(
    firefox_136_headers,
    firefox_136_ajax_headers,
    firefox_136_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0",
    "136"
);
firefox_header_set!(
    firefox_137_headers,
    firefox_137_ajax_headers,
    firefox_137_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0",
    "137"
);
firefox_header_set!(
    firefox_138_headers,
    firefox_138_ajax_headers,
    firefox_138_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0",
    "138"
);
firefox_header_set!(
    firefox_139_headers,
    firefox_139_ajax_headers,
    firefox_139_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:139.0) Gecko/20100101 Firefox/139.0",
    "139"
);
firefox_header_set!(
    firefox_140_headers,
    firefox_140_ajax_headers,
    firefox_140_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
    "140"
);
firefox_header_set!(
    firefox_141_headers,
    firefox_141_ajax_headers,
    firefox_141_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0",
    "141"
);
firefox_header_set!(
    firefox_142_headers,
    firefox_142_ajax_headers,
    firefox_142_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0",
    "142"
);
firefox_header_set!(
    firefox_143_headers,
    firefox_143_ajax_headers,
    firefox_143_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0",
    "143"
);
firefox_header_set!(
    firefox_144_headers,
    firefox_144_ajax_headers,
    firefox_144_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0",
    "144"
);
firefox_header_set!(
    firefox_145_headers,
    firefox_145_ajax_headers,
    firefox_145_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:145.0) Gecko/20100101 Firefox/145.0",
    "145"
);
firefox_header_set!(
    firefox_146_headers,
    firefox_146_ajax_headers,
    firefox_146_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0",
    "146"
);
firefox_header_set!(
    firefox_147_headers,
    firefox_147_ajax_headers,
    firefox_147_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0",
    "147"
);
firefox_header_set!(
    firefox_148_headers,
    firefox_148_ajax_headers,
    firefox_148_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0",
    "148"
);
firefox_header_set!(
    firefox_149_headers,
    firefox_149_ajax_headers,
    firefox_149_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0",
    "149"
);
firefox_header_set!(
    firefox_150_headers,
    firefox_150_ajax_headers,
    firefox_150_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:150.0) Gecko/20100101 Firefox/150.0",
    "150"
);
firefox_header_set!(
    firefox_151_headers,
    firefox_151_ajax_headers,
    firefox_151_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:151.0) Gecko/20100101 Firefox/151.0",
    "151"
);
firefox_header_set!(
    firefox_esr_115_headers,
    firefox_esr_115_ajax_headers,
    firefox_esr_115_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:115.0) Gecko/20100101 Firefox/115.0",
    "115 ESR"
);
firefox_header_set!(
    firefox_esr_128_headers,
    firefox_esr_128_ajax_headers,
    firefox_esr_128_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
    "128 ESR"
);
firefox_header_set!(
    firefox_esr_140_headers,
    firefox_esr_140_ajax_headers,
    firefox_esr_140_form_headers,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
    "140 ESR"
);
