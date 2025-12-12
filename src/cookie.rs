//! RFC 6265 compliant cookie handling.
//!
//! Manual cookie storage and management - no automatic cookie engine.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use chrono::{DateTime, TimeZone, Utc};
use url::Url;

use crate::error::{Error, Result};

/// SameSite attribute for cookies (RFC 6265bis).
///
/// Controls whether cookies are sent with cross-site requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SameSite {
    /// Cookie sent only for same-site requests.
    Strict,
    /// Cookie sent for same-site requests and top-level navigation.
    Lax,
    /// Cookie sent for all requests (requires Secure attribute).
    None,
}

/// RFC 6265 compliant cookie representation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<SameSite>,
    pub expires: Option<DateTime<Utc>>,
    pub max_age: Option<i64>,
    pub host_only: bool,
    pub source_url: Option<String>,
    pub raw_header: Option<String>,
    /// Creation time for sorting per RFC 6265 Section 5.4
    pub creation_time: DateTime<Utc>,
}

impl Cookie {
    pub fn new(
        name: impl Into<String>,
        value: impl Into<String>,
        domain: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: normalize_domain(&domain.into()),
            path: "/".to_string(),
            secure: false,
            http_only: false,
            same_site: None,
            expires: None,
            max_age: None,
            host_only: true,
            source_url: None,
            raw_header: None,
            creation_time: Utc::now(),
        }
    }

    /// Builder-style method to set the path.
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// Builder-style method to set the secure flag.
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Builder-style method to set the http_only flag.
    pub fn with_http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    /// Builder-style method to set the same_site attribute.
    pub fn with_same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = Some(same_site);
        self
    }

    /// Builder-style method to set the expires time.
    pub fn with_expires(mut self, expires: DateTime<Utc>) -> Self {
        self.expires = Some(expires);
        self
    }

    /// Builder-style method to set the host_only flag.
    pub fn with_host_only(mut self, host_only: bool) -> Self {
        self.host_only = host_only;
        self
    }

    pub fn from_set_cookie_header(header: &str, request_url: &str) -> Result<Self> {
        let parsed_url = Url::parse(request_url).map_err(|e| Error::CookieParse(e.to_string()))?;
        let request_domain = parsed_url
            .host_str()
            .ok_or_else(|| Error::CookieParse("No host in URL".to_string()))?;

        let parts: Vec<&str> = header.split(';').map(str::trim).collect();
        if parts.is_empty() {
            return Err(Error::CookieParse("Empty cookie header".to_string()));
        }

        let (name, value) = match parts[0].split_once('=') {
            Some((n, v)) => (n.trim().to_string(), v.trim().to_string()),
            None => return Err(Error::CookieParse("No = in cookie".to_string())),
        };

        if name.is_empty() {
            return Err(Error::CookieParse("Empty cookie name".to_string()));
        }

        let mut cookie = Cookie::new(name, value, request_domain);
        cookie.raw_header = Some(header.to_string());
        cookie.source_url = Some(request_url.to_string());

        // Track whether Domain attribute was present (RFC 6265 host-only-flag)
        let mut domain_attr_present = false;

        for attr in parts.iter().skip(1) {
            let attr_lower = attr.to_lowercase();
            if attr_lower == "secure" {
                cookie.secure = true;
            } else if attr_lower == "httponly" {
                cookie.http_only = true;
            } else if let Some((key, val)) = attr.split_once('=') {
                match key.trim().to_lowercase().as_str() {
                    "domain" => {
                        cookie.domain = normalize_domain(val.trim());
                        domain_attr_present = true;
                    }
                    "path" => cookie.path = val.trim().to_string(),
                    "expires" => cookie.expires = parse_cookie_date(val.trim()),
                    "max-age" => cookie.max_age = val.trim().parse().ok(),
                    "samesite" => {
                        let ss_str = val.trim();
                        cookie.same_site = match ss_str.to_lowercase().as_str() {
                            "strict" => Some(SameSite::Strict),
                            "lax" => Some(SameSite::Lax),
                            "none" => Some(SameSite::None),
                            _ => None,
                        };
                    }
                    _ => {}
                }
            }
        }

        // RFC 6265 Section 5.3: host-only-flag is false if Domain attribute present, true otherwise
        cookie.host_only = !domain_attr_present;

        // RFC 6265 Section 5.3: Max-Age takes precedence over Expires
        // Convert Max-Age to expires immediately
        if let Some(max_age) = cookie.max_age {
            if max_age > 0 {
                cookie.expires = Some(Utc::now() + chrono::Duration::seconds(max_age));
            } else {
                // Max-Age=0 means delete cookie
                cookie.expires = Some(Utc::now() - chrono::Duration::seconds(1));
            }
        }

        // RFC 6265 Section 5.3: Reject cookies for public suffixes
        if is_public_suffix(&cookie.domain) {
            return Err(Error::CookieParse(format!(
                "Cannot set cookie for public suffix: {}",
                cookie.domain
            )));
        }

        // RFC 6265bis: SameSite=None requires Secure
        if cookie.same_site == Some(SameSite::None) && !cookie.secure {
            return Err(Error::CookieParse(
                "SameSite=None requires Secure attribute".to_string(),
            ));
        }

        Ok(cookie)
    }

    pub fn matches_url(&self, url: &str) -> bool {
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return false,
        };
        let request_domain = match parsed.host_str() {
            Some(h) => h.to_lowercase(),
            None => return false,
        };

        // Check secure flag (HTTPS-only cookies)
        if self.secure && parsed.scheme() != "https" {
            return false;
        }

        // Check expiration
        if let Some(expires) = self.expires {
            if expires < Utc::now() {
                return false;
            }
        }

        // RFC 6265 domain matching with host_only flag
        if !self.domain_matches(&request_domain) {
            return false;
        }

        // RFC 6265 path matching
        let request_path = parsed.path();
        if !self.path_matches(request_path) {
            return false;
        }

        true
    }

    /// RFC 6265 Section 5.1.3: Domain Matching
    /// Returns true if request_domain matches this cookie's domain.
    pub fn domain_matches(&self, request_domain: &str) -> bool {
        let cookie_domain = self.domain.to_lowercase();
        let request_domain_lower = request_domain.to_lowercase();

        // Host-only cookie: must match exactly
        if self.host_only {
            return request_domain_lower == cookie_domain;
        }

        // Domain cookie: exact match
        if request_domain_lower == cookie_domain {
            return true;
        }

        // Domain cookie: subdomain match
        // Example: request_domain = "app.slack.com", cookie_domain = "slack.com"
        // We check if request_domain ends with ".slack.com"
        if request_domain_lower.len() > cookie_domain.len() {
            let expected_suffix = format!(".{}", cookie_domain);
            if request_domain_lower.ends_with(&expected_suffix) {
                return true;
            }
        }

        false
    }

    /// RFC 6265 Section 5.1.4: Path Matching
    /// Returns true if request_path matches this cookie's path.
    pub fn path_matches(&self, request_path: &str) -> bool {
        let cookie_path = &self.path;

        // Exact match
        if request_path == cookie_path {
            return true;
        }

        // Cookie path must be a prefix of request path
        if !request_path.starts_with(cookie_path) {
            return false;
        }

        // If cookie path ends with '/', it's a valid prefix
        if cookie_path.ends_with('/') {
            return true;
        }

        // If cookie path doesn't end with '/', the next character in request path
        // must be '/' to avoid matching "/apiv2" with cookie path "/api"
        if let Some(next_char) = request_path.chars().nth(cookie_path.len()) {
            return next_char == '/';
        }

        false
    }

    pub fn to_netscape_line(&self) -> String {
        // Netscape format: include_subdomains is TRUE for domain cookies (host_only=false)
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.domain,
            if self.host_only { "FALSE" } else { "TRUE" },
            self.path,
            if self.secure { "TRUE" } else { "FALSE" },
            self.expires
                .map(|dt| dt.timestamp().to_string())
                .unwrap_or_else(|| "0".to_string()),
            self.name,
            self.value
        )
    }

    pub fn from_netscape_line(line: &str) -> Result<Self> {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 7 {
            return Err(Error::CookieParse(format!(
                "Invalid Netscape format: expected 7 fields, got {}",
                parts.len()
            )));
        }
        // Netscape format field 1 (index 1) is include_subdomains flag
        // TRUE means domain cookie (host_only=false), FALSE means host-only (host_only=true)
        let include_subdomains = parts[1].eq_ignore_ascii_case("true");
        Ok(Cookie {
            name: parts[5].to_string(),
            value: parts[6].to_string(),
            domain: normalize_domain(parts[0]),
            path: parts[2].to_string(),
            secure: parts[3].eq_ignore_ascii_case("true"),
            http_only: false,
            same_site: None,
            expires: parts[4]
                .parse::<i64>()
                .ok()
                .filter(|&ts| ts > 0)
                .and_then(|ts| Utc.timestamp_opt(ts, 0).single()),
            max_age: None,
            host_only: !include_subdomains,
            source_url: None,
            raw_header: None,
            creation_time: Utc::now(),
        })
    }

    pub fn value_hash(&self) -> String {
        hash_cookie_value(&self.value)
    }
}

/// Hash a cookie value using SHA-256 (8-digit hex).
///
/// Uses first 4 bytes (8 hex characters) for a short hash.
/// This is useful for tracking and debugging cookie values without storing the full value.
///
/// # Arguments
///
/// * `value` - Cookie value to hash
///
/// # Returns
///
/// 8-character hexadecimal hash string.
pub fn hash_cookie_value(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let result = Sha256::digest(value.as_bytes());
    result[..4].iter().map(|b| format!("{:02x}", b)).collect()
}

impl fmt::Display for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.value)
    }
}

/// Cookie jar for manual cookie management.
#[derive(Debug, Default, Clone)]
pub struct CookieJar {
    cookies: HashMap<String, Vec<Cookie>>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store(&mut self, cookie: Cookie) {
        let list = self.cookies.entry(cookie.domain.clone()).or_default();

        // RFC 6265 Section 5.3:
        // If the cookie store contains a cookie with the same name, domain, and path as the new cookie:
        // 1. Let old-cookie be the existing cookie...
        // 2. Remove old-cookie
        // 3. Insert new-cookie
        if let Some(pos) = list
            .iter()
            .position(|c| c.name == cookie.name && c.path == cookie.path)
        {
            list[pos] = cookie;
        } else {
            list.push(cookie);
        }
    }

    pub fn add(&mut self, cookie: Cookie) {
        self.store(cookie);
    }

    pub fn cookies(&self) -> Vec<&Cookie> {
        self.cookies.values().flat_map(|v| v.iter()).collect()
    }

    pub fn cookies_for_url(&self, url: &str) -> Vec<&Cookie> {
        self.cookies
            .values()
            .flat_map(|v| v.iter())
            .filter(|c| c.matches_url(url))
            .collect()
    }

    pub fn build_cookie_header(&self, url: &str) -> Option<String> {
        let mut cookies = self.cookies_for_url(url);
        if cookies.is_empty() {
            return None;
        }

        // RFC 6265 Section 5.4: Sort cookies by longest path first, then by creation time (oldest first)
        cookies.sort_by(|a, b| {
            b.path
                .len()
                .cmp(&a.path.len())
                .then_with(|| a.creation_time.cmp(&b.creation_time))
        });

        Some(
            cookies
                .iter()
                .map(|c| format!("{}={}", c.name, c.value))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    pub fn store_from_headers(&mut self, headers: &[String], request_url: &str) {
        for header in headers {
            if let Some(value) = header
                .strip_prefix("Set-Cookie:")
                .or_else(|| header.strip_prefix("set-cookie:"))
            {
                if let Ok(cookie) = Cookie::from_set_cookie_header(value.trim(), request_url) {
                    self.store(cookie);
                }
            }
        }
    }

    pub async fn save_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let mut file = tokio::fs::File::create(path).await.map_err(Error::Io)?;
        file.write_all(b"# Netscape HTTP Cookie File\n")
            .await
            .map_err(Error::Io)?;
        for cookies in self.cookies.values() {
            for cookie in cookies {
                let line = format!("{}\n", cookie.to_netscape_line());
                file.write_all(line.as_bytes()).await.map_err(Error::Io)?;
            }
        }
        Ok(())
    }

    pub async fn load_from_file(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let file = tokio::fs::File::open(path).await.map_err(Error::Io)?;
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        while reader.read_line(&mut line).await.map_err(Error::Io)? > 0 {
            let trimmed = line.trim_end();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                if let Ok(cookie) = Cookie::from_netscape_line(trimmed) {
                    self.store(cookie);
                }
            }
            line.clear();
        }
        Ok(())
    }

    pub fn get(&self, domain: &str, name: &str) -> Option<&Cookie> {
        // Return the first match (ambiguous without path)
        self.cookies
            .get(&normalize_domain(domain))?
            .iter()
            .find(|c| c.name == name)
    }

    pub fn remove(&mut self, domain: &str, name: &str) -> Option<Cookie> {
        // Remove the first match (ambiguous without path)
        let list = self.cookies.get_mut(&normalize_domain(domain))?;
        if let Some(pos) = list.iter().position(|c| c.name == name) {
            Some(list.remove(pos))
        } else {
            None
        }
    }

    pub fn clear(&mut self) {
        self.cookies.clear();
    }
    pub fn len(&self) -> usize {
        self.cookies.values().map(|v| v.len()).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }
}

fn normalize_domain(domain: &str) -> String {
    domain
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_lowercase()
}

fn parse_cookie_date(date_str: &str) -> Option<DateTime<Utc>> {
    // RFC 6265 Section 5.1.1: Cookie date formats
    // Try RFC 1123, RFC 850, ANSI C asctime(), and common variations
    const FORMATS: &[&str] = &[
        "%a, %d %b %Y %H:%M:%S GMT", // RFC 1123 (e.g., "Mon, 01 Jan 2024 12:00:00 GMT")
        "%A, %d-%b-%y %H:%M:%S GMT", // RFC 850 (e.g., "Monday, 01-Jan-24 12:00:00 GMT")
        "%a %b %e %H:%M:%S %Y",      // ANSI C asctime() (e.g., "Mon Jan  1 12:00:00 2024")
        "%a, %d-%b-%Y %H:%M:%S GMT", // RFC 1036 variation
        "%d %b %Y %H:%M:%S GMT",     // No weekday prefix
        "%a, %d %b %Y %H:%M:%S %z",  // With timezone offset
        "%Y-%m-%dT%H:%M:%SZ",        // ISO 8601 UTC
        "%Y-%m-%dT%H:%M:%S%.fZ",     // ISO 8601 with fractional seconds
    ];

    for fmt in FORMATS {
        if let Ok(dt) = chrono::DateTime::parse_from_str(date_str, fmt) {
            return Some(dt.with_timezone(&Utc));
        }
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(date_str, fmt) {
            return Some(chrono::TimeZone::from_utc_datetime(&Utc, &dt));
        }
    }

    // Fallback: try parsing as Unix timestamp
    date_str
        .parse::<i64>()
        .ok()
        .and_then(|ts| Utc.timestamp_opt(ts, 0).single())
}

/// Check if a domain is a public suffix per RFC 6265 Section 5.3.
/// Prevents setting cookies on TLDs like ".com" or ".co.uk".
fn is_public_suffix(domain: &str) -> bool {
    // Remove leading dot if present
    let domain_clean = domain.strip_prefix('.').unwrap_or(domain);

    // Use psl to check if this is a public suffix
    psl::suffix(domain_clean.as_bytes())
        .map(|suffix| {
            // Check if the entire domain is the public suffix
            suffix.is_known() && suffix.as_bytes() == domain_clean.as_bytes()
        })
        .unwrap_or(false)
}
