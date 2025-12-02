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

/// RFC 6265 compliant cookie representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub max_age: Option<i64>,
    pub source_url: Option<String>,
    pub raw_header: Option<String>,
}

impl Cookie {
    pub fn new(name: impl Into<String>, value: impl Into<String>, domain: impl Into<String>) -> Self {
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
            source_url: None,
            raw_header: None,
        }
    }

    pub fn from_set_cookie_header(header: &str, request_url: &str) -> Result<Self> {
        let parsed_url = Url::parse(request_url).map_err(|e| Error::CookieParse(e.to_string()))?;
        let request_domain = parsed_url.host_str()
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

        for attr in parts.iter().skip(1) {
            let attr_lower = attr.to_lowercase();
            if attr_lower == "secure" {
                cookie.secure = true;
            } else if attr_lower == "httponly" {
                cookie.http_only = true;
            } else if let Some((key, val)) = attr.split_once('=') {
                match key.trim().to_lowercase().as_str() {
                    "domain" => cookie.domain = normalize_domain(val.trim()),
                    "path" => cookie.path = val.trim().to_string(),
                    "expires" => cookie.expires = parse_cookie_date(val.trim()),
                    "max-age" => cookie.max_age = val.trim().parse().ok(),
                    "samesite" => cookie.same_site = Some(val.trim().to_string()),
                    _ => {}
                }
            }
        }
        Ok(cookie)
    }

    pub fn matches_url(&self, url: &str) -> bool {
        let parsed = match Url::parse(url) { Ok(u) => u, Err(_) => return false };
        let request_domain = match parsed.host_str() { Some(h) => h.to_lowercase(), None => return false };

        if self.secure && parsed.scheme() != "https" { return false; }
        if let Some(expires) = self.expires { if expires < Utc::now() { return false; } }

        let cookie_domain = self.domain.to_lowercase();
        if request_domain != cookie_domain && !request_domain.ends_with(&format!(".{}", cookie_domain)) {
            return false;
        }

        let request_path = parsed.path();
        request_path == self.path || request_path.starts_with(&format!("{}/", self.path.trim_end_matches('/')))
    }

    pub fn to_netscape_line(&self) -> String {
        format!("{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.domain,
            if self.domain.starts_with('.') { "TRUE" } else { "FALSE" },
            self.path,
            if self.secure { "TRUE" } else { "FALSE" },
            self.expires.map(|dt| dt.timestamp().to_string()).unwrap_or_else(|| "0".to_string()),
            self.name,
            self.value
        )
    }

    pub fn from_netscape_line(line: &str) -> Result<Self> {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 7 {
            return Err(Error::CookieParse(format!("Invalid Netscape format: expected 7 fields, got {}", parts.len())));
        }
        Ok(Cookie {
            name: parts[5].to_string(),
            value: parts[6].to_string(),
            domain: normalize_domain(parts[0]),
            path: parts[2].to_string(),
            secure: parts[3].eq_ignore_ascii_case("true"),
            http_only: false,
            same_site: None,
            expires: parts[4].parse::<i64>().ok().filter(|&ts| ts > 0).and_then(|ts| Utc.timestamp_opt(ts, 0).single()),
            max_age: None,
            source_url: None,
            raw_header: None,
        })
    }

    pub fn value_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let result = Sha256::digest(self.value.as_bytes());
        result[..4].iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl fmt::Display for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.value)
    }
}

/// Cookie jar for manual cookie management.
#[derive(Debug, Default, Clone)]
pub struct CookieJar {
    cookies: HashMap<String, HashMap<String, Cookie>>,
}

impl CookieJar {
    pub fn new() -> Self { Self::default() }

    pub fn store(&mut self, cookie: Cookie) {
        self.cookies.entry(cookie.domain.clone()).or_default().insert(cookie.name.clone(), cookie);
    }

    pub fn add(&mut self, cookie: Cookie) { self.store(cookie); }

    pub fn cookies(&self) -> Vec<&Cookie> {
        self.cookies.values().flat_map(|m| m.values()).collect()
    }

    pub fn cookies_for_url(&self, url: &str) -> Vec<&Cookie> {
        self.cookies.values().flat_map(|m| m.values()).filter(|c| c.matches_url(url)).collect()
    }

    pub fn build_cookie_header(&self, url: &str) -> Option<String> {
        let cookies = self.cookies_for_url(url);
        if cookies.is_empty() { return None; }
        Some(cookies.iter().map(|c| format!("{}={}", c.name, c.value)).collect::<Vec<_>>().join("; "))
    }

    pub fn store_from_headers(&mut self, headers: &[String], request_url: &str) {
        for header in headers {
            if let Some(value) = header.strip_prefix("Set-Cookie:").or_else(|| header.strip_prefix("set-cookie:")) {
                if let Ok(cookie) = Cookie::from_set_cookie_header(value.trim(), request_url) {
                    self.store(cookie);
                }
            }
        }
    }

    pub async fn save_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let mut file = tokio::fs::File::create(path).await
            .map_err(|e| Error::Io(e))?;
        file.write_all(b"# Netscape HTTP Cookie File\n").await
            .map_err(|e| Error::Io(e))?;
        for cookies in self.cookies.values() {
            for cookie in cookies.values() {
                let line = format!("{}\n", cookie.to_netscape_line());
                file.write_all(line.as_bytes()).await
                    .map_err(|e| Error::Io(e))?;
            }
        }
        Ok(())
    }

    pub async fn load_from_file(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let file = tokio::fs::File::open(path).await
            .map_err(|e| Error::Io(e))?;
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        while reader.read_line(&mut line).await
            .map_err(|e| Error::Io(e))? > 0 {
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
        self.cookies.get(&normalize_domain(domain))?.get(name)
    }

    pub fn remove(&mut self, domain: &str, name: &str) -> Option<Cookie> {
        self.cookies.get_mut(&normalize_domain(domain))?.remove(name)
    }

    pub fn clear(&mut self) { self.cookies.clear(); }
    pub fn len(&self) -> usize { self.cookies.values().map(|m| m.len()).sum() }
    pub fn is_empty(&self) -> bool { self.cookies.is_empty() }
}

fn normalize_domain(domain: &str) -> String {
    domain.strip_prefix('.').unwrap_or(domain).to_lowercase()
}

fn parse_cookie_date(date_str: &str) -> Option<DateTime<Utc>> {
    for fmt in ["%a, %d %b %Y %H:%M:%S GMT", "%a, %d-%b-%y %H:%M:%S GMT", "%Y-%m-%dT%H:%M:%SZ"] {
        if let Ok(dt) = chrono::DateTime::parse_from_str(date_str, fmt) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    date_str.parse::<i64>().ok().and_then(|ts| Utc.timestamp_opt(ts, 0).single())
}
