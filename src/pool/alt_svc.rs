//! Alt-Svc header parsing and caching for HTTP/3 discovery.

use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::RwLock;
use std::sync::Arc;

/// Parsed Alt-Svc entry (RFC 7838)
#[derive(Debug, Clone)]
pub struct AltSvcEntry {
    /// Protocol identifier (e.g., "h3", "h3-29", "h2")
    pub protocol: String,
    /// Alternative host (None means same host)
    pub host: Option<String>,
    /// Alternative port
    pub port: u16,
    /// Max age in seconds
    pub max_age: u64,
    /// When this entry was received
    pub received_at: Instant,
    /// Persist across restarts (persist parameter)
    pub persist: bool,
}

impl AltSvcEntry {
    /// Check if this entry has expired
    pub fn is_expired(&self) -> bool {
        let age = self.received_at.elapsed().as_secs();
        age >= self.max_age
    }
    
    /// Check if this is HTTP/3
    pub fn is_h3(&self) -> bool {
        self.protocol == "h3" || self.protocol.starts_with("h3-")
    }
}

/// Alt-Svc cache for HTTP/3 discovery
pub struct AltSvcCache {
    entries: Arc<RwLock<HashMap<String, Vec<AltSvcEntry>>>>,
    default_max_age: u64,
}

impl AltSvcCache {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            default_max_age: 86400, // 24 hours default
        }
    }
    
    /// Parse Alt-Svc header and store entries for origin
    pub async fn parse_and_store(&self, origin: &str, header: &str) -> Vec<AltSvcEntry> {
        // Handle "clear" directive
        if header.trim() == "clear" {
            self.clear_origin(origin).await;
            return vec![];
        }
        
        let entries = parse_alt_svc(header, self.default_max_age);
        
        if !entries.is_empty() {
            let mut cache = self.entries.write().await;
            cache.insert(origin.to_string(), entries.clone());
        }
        
        entries
    }
    
    /// Get best HTTP/3 alternative for origin
    pub async fn get_h3_alternative(&self, origin: &str) -> Option<AltSvcEntry> {
        let cache = self.entries.read().await;
        cache.get(origin)
            .and_then(|entries| {
                entries.iter().find(|e| e.is_h3() && !e.is_expired())
                    .cloned()
            })
    }
    
    /// Clear entries for an origin
    pub async fn clear_origin(&self, origin: &str) {
        let mut cache = self.entries.write().await;
        cache.remove(origin);
    }
    
    /// Remove expired entries from cache
    pub async fn cleanup_expired(&self) {
        let mut cache = self.entries.write().await;
        for entries in cache.values_mut() {
            entries.retain(|e| !e.is_expired());
        }
        cache.retain(|_, entries| !entries.is_empty());
    }
}

/// Parse Alt-Svc header value into a vector of entries
///
/// # Examples
///
/// ```
/// use specter::pool::alt_svc::parse_alt_svc;
///
/// let header = r#"h3=":443"; ma=86400, h3-29="alt.com:8443"; persist=1"#;
/// let entries = parse_alt_svc(header, 3600);
/// ```
pub fn parse_alt_svc(header: &str, default_max_age: u64) -> Vec<AltSvcEntry> {
    let mut entries = Vec::new();
    let received_at = Instant::now();
    
    // Split by commas to get individual alternatives
    let alternatives: Vec<&str> = header.split(',').collect();
    
    for alt in alternatives {
        let alt = alt.trim();
        if alt.is_empty() {
            continue;
        }
        
        // Split into protocol=value and parameters
        let parts: Vec<&str> = alt.split(';').collect();
        if parts.is_empty() {
            continue;
        }
        
        let main_part = parts[0].trim();
        
        // Parse protocol=value
        let Some(equals_pos) = main_part.find('=') else {
            continue; // Skip malformed entries without =
        };
        
        let protocol = main_part[..equals_pos].trim();
        if protocol.is_empty() {
            continue;
        }
        
        let value_part = main_part[equals_pos + 1..].trim();
        
        // Extract host:port from quoted value
        let (host, port) = match parse_quoted_value(value_part) {
            Some((h, p)) => (h, p),
            None => continue, // Skip if value parsing fails
        };
        
        // Parse parameters (ma, persist)
        let mut max_age = default_max_age;
        let mut persist = false;
        
        for param_part in parts.iter().skip(1) {
            let param_part = param_part.trim();
            if param_part.is_empty() {
                continue;
            }
            
            // Parse key=value parameter
            if let Some(param_equals) = param_part.find('=') {
                let key = param_part[..param_equals].trim();
                let value = param_part[param_equals + 1..].trim();
                
                match key {
                    "ma" => {
                        if let Ok(age) = value.parse::<u64>() {
                            max_age = age;
                        }
                    }
                    "persist" => {
                        persist = value == "1" || value.eq_ignore_ascii_case("true");
                    }
                    _ => {
                        // Unknown parameter, ignore
                    }
                }
            }
        }
        
        entries.push(AltSvcEntry {
            protocol: protocol.to_string(),
            host,
            port,
            max_age,
            received_at,
            persist,
        });
    }
    
    entries
}

/// Parse quoted value to extract host and port
///
/// Handles formats:
/// - `":443"` -> (None, 443)
/// - `"alt.example.com:443"` -> (Some("alt.example.com"), 443)
/// - `"alt.example.com"` -> (Some("alt.example.com"), 443) [default port]
fn parse_quoted_value(value: &str) -> Option<(Option<String>, u16)> {
    let value = value.trim();
    
    // Remove quotes if present
    let unquoted = if value.starts_with('"') && value.ends_with('"') {
        &value[1..value.len() - 1]
    } else {
        value
    };
    
    let unquoted = unquoted.trim();
    
    // Check if it starts with ':' (same-origin case)
    if let Some(port_str) = unquoted.strip_prefix(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return Some((None, port));
        }
        return None;
    }
    
    // Check if it's a pure numeric string (treat as :port for robustness)
    if unquoted.parse::<u16>().is_ok() && unquoted.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(port) = unquoted.parse::<u16>() {
            return Some((None, port));
        }
    }
    
    // Parse host:port
    if let Some(colon_pos) = unquoted.rfind(':') {
        let host = unquoted[..colon_pos].trim();
        let port_str = unquoted[colon_pos + 1..].trim();
        
        if host.is_empty() {
            // Handle ":port" case (should have been caught above, but double-check)
            if let Ok(port) = port_str.parse::<u16>() {
                return Some((None, port));
            }
            return None;
        }
        
        if let Ok(port) = port_str.parse::<u16>() {
            return Some((Some(host.to_string()), port));
        }
    } else {
        // No port specified, assume default HTTPS port
        if !unquoted.is_empty() {
            return Some((Some(unquoted.to_string()), 443));
        }
    }
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_simple_h3() {
        let header = r#"h3=":443"; ma=86400"#;
        let entries = parse_alt_svc(header, 3600);
        
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protocol, "h3");
        assert_eq!(entries[0].host, None);
        assert_eq!(entries[0].port, 443);
        assert_eq!(entries[0].max_age, 86400);
        assert!(entries[0].is_h3());
    }
    
    #[test]
    fn test_parse_with_host() {
        let header = r#"h3="alt.example.com:443"; ma=3600; persist=1"#;
        let entries = parse_alt_svc(header, 86400);
        
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protocol, "h3");
        assert_eq!(entries[0].host, Some("alt.example.com".to_string()));
        assert_eq!(entries[0].port, 443);
        assert_eq!(entries[0].max_age, 3600);
        assert!(entries[0].persist);
    }
    
    #[test]
    fn test_parse_multiple_alternatives() {
        let header = r#"h3=":443"; ma=86400, h3-29=":443"; ma=86400"#;
        let entries = parse_alt_svc(header, 3600);
        
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].protocol, "h3");
        assert_eq!(entries[1].protocol, "h3-29");
        assert!(entries[0].is_h3());
        assert!(entries[1].is_h3());
    }
    
    #[test]
    fn test_parse_mixed_protocols() {
        let header = r#"h3=":443", h2=":443""#;
        let entries = parse_alt_svc(header, 86400);
        
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].protocol, "h3");
        assert_eq!(entries[1].protocol, "h2");
        assert!(entries[0].is_h3());
        assert!(!entries[1].is_h3());
    }
    
    #[test]
    fn test_parse_without_quotes() {
        // Some servers may omit quotes, handle gracefully
        let header = r#"h3=:443; ma=86400"#;
        let entries = parse_alt_svc(header, 3600);
        
        // Should still parse (unquoted value)
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protocol, "h3");
        assert_eq!(entries[0].port, 443);
    }
    
    #[test]
    fn test_parse_default_max_age() {
        let header = r#"h3=":443""#;
        let entries = parse_alt_svc(header, 7200);
        
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].max_age, 7200); // Uses default
    }
    
    #[test]
    fn test_parse_persist_false() {
        let header = r#"h3=":443"; persist=0"#;
        let entries = parse_alt_svc(header, 86400);
        
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].persist);
    }
    
    #[test]
    fn test_parse_persist_true() {
        let header = r#"h3=":443"; persist=1"#;
        let entries = parse_alt_svc(header, 86400);
        
        assert_eq!(entries.len(), 1);
        assert!(entries[0].persist);
    }
    
    #[test]
    fn test_parse_custom_port() {
        let header = r#"h3="alt.com:8443"; ma=86400"#;
        let entries = parse_alt_svc(header, 3600);
        
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, Some("alt.com".to_string()));
        assert_eq!(entries[0].port, 8443);
    }
    
    #[test]
    fn test_parse_host_without_port() {
        let header = r#"h3="alt.example.com""#;
        let entries = parse_alt_svc(header, 86400);
        
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, Some("alt.example.com".to_string()));
        assert_eq!(entries[0].port, 443); // Default HTTPS port
    }
    
    #[test]
    fn test_parse_malformed_entries() {
        // Missing protocol
        let header = r#"=":443""#;
        let entries = parse_alt_svc(header, 86400);
        assert_eq!(entries.len(), 0);
        
        // Missing equals
        let header = r#"h3":443""#;
        let entries = parse_alt_svc(header, 86400);
        assert_eq!(entries.len(), 0);
        
        // Invalid port
        let header = r#"h3=":99999""#;
        let entries = parse_alt_svc(header, 86400);
        assert_eq!(entries.len(), 0);
    }
    
    #[test]
    fn test_parse_empty_and_whitespace() {
        let header = "";
        let entries = parse_alt_svc(header, 86400);
        assert_eq!(entries.len(), 0);
        
        let header = "   ";
        let entries = parse_alt_svc(header, 86400);
        assert_eq!(entries.len(), 0);
        
        let header = r#"h3=":443", , h2=":443""#;
        let entries = parse_alt_svc(header, 86400);
        assert_eq!(entries.len(), 2); // Empty alternative skipped
    }
    
    #[tokio::test]
    async fn test_cache_operations() {
        let cache = AltSvcCache::new();
        
        // Store entries
        let header = r#"h3=":443"; ma=3600"#;
        let entries = cache.parse_and_store("https://example.com", header).await;
        assert_eq!(entries.len(), 1);
        
        // Retrieve H3 alternative
        let h3_entry = cache.get_h3_alternative("https://example.com").await;
        assert!(h3_entry.is_some());
        assert_eq!(h3_entry.unwrap().protocol, "h3");
        
        // Clear origin
        cache.clear_origin("https://example.com").await;
        let h3_entry = cache.get_h3_alternative("https://example.com").await;
        assert!(h3_entry.is_none());
    }
    
    #[tokio::test]
    async fn test_cache_clear_directive() {
        let cache = AltSvcCache::new();
        
        // Store entries first
        let header = r#"h3=":443"; ma=3600"#;
        cache.parse_and_store("https://example.com", header).await;
        
        // Clear directive
        let entries = cache.parse_and_store("https://example.com", "clear").await;
        assert_eq!(entries.len(), 0);
        
        // Verify cleared
        let h3_entry = cache.get_h3_alternative("https://example.com").await;
        assert!(h3_entry.is_none());
    }
    
    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = AltSvcCache::new();
        
        // Store entry with very short max_age
        let header = r#"h3=":443"; ma=1"#;
        cache.parse_and_store("https://example.com", header).await;
        
        // Should be available immediately
        let h3_entry = cache.get_h3_alternative("https://example.com").await;
        assert!(h3_entry.is_some());
        
        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        
        // Should be expired
        let h3_entry = cache.get_h3_alternative("https://example.com").await;
        assert!(h3_entry.is_none());
        
        // Cleanup should remove expired entries
        cache.cleanup_expired().await;
        let h3_entry = cache.get_h3_alternative("https://example.com").await;
        assert!(h3_entry.is_none());
    }
}
