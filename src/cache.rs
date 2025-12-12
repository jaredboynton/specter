use crate::response::Response;
use http::Method;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub response: Response,
    pub expires: SystemTime,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug)]
pub enum CacheStatus {
    /// Response is fresh and can be used directly.
    Fresh(Response),
    /// Response is stale but can be validated using conditional headers.
    /// (Response, ETag, Last-Modified)
    Revalidate(Response, Option<String>, Option<String>),
    /// Cache miss.
    Miss,
}

pub struct HttpCache {
    // In-memory cache
    entries: std::collections::HashMap<String, CacheEntry>,
}

impl HttpCache {
    pub fn new() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
        }
    }

    pub fn get(&self, method: &Method, url: &str) -> CacheStatus {
        if method != Method::GET {
            return CacheStatus::Miss;
        }

        if let Some(entry) = self.entries.get(url) {
            if entry.expires > SystemTime::now() {
                return CacheStatus::Fresh(entry.response.clone());
            } else {
                // Stale, check if revalidation is possible
                if entry.etag.is_some() || entry.last_modified.is_some() {
                    return CacheStatus::Revalidate(
                        entry.response.clone(),
                        entry.etag.clone(),
                        entry.last_modified.clone(),
                    );
                }
            }
        }
        CacheStatus::Miss
    }

    pub fn store(&mut self, url: &str, response: &Response) {
        // Parse Cache-Control
        if let Some(cc) = response.get_header("cache-control") {
            if cc.contains("no-store") {
                return;
            }

            // Determine TTL (simplified Max-Age parsing)
            // Look for "max-age=N"
            let ttl = if let Some(pos) = cc.find("max-age=") {
                let start = pos + 8;
                let end = cc[start..].find(',').map(|i| start + i).unwrap_or(cc.len());
                cc[start..end].trim().parse::<u64>().unwrap_or(0)
            } else {
                0
            };

            if ttl == 0 {
                // No implicit caching for now unless heuristics added
                return;
            }

            let expires = SystemTime::now() + Duration::from_secs(ttl);

            let etag = response.get_header("etag").map(|s| s.to_string());
            let last_modified = response.get_header("last-modified").map(|s| s.to_string());

            let entry = CacheEntry {
                response: response.clone(),
                expires,
                etag,
                last_modified,
            };
            self.entries.insert(url.to_string(), entry);
        }
    }
}
