//! TLS session resumption and caching.
//!
//! Implements session ticket caching for TLS 1.2 and TLS 1.3 session resumption.
//! Browsers cache session tickets to enable 0-RTT (early data) and faster handshakes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// TLS session ticket cache.
///
/// Stores session tickets per host to enable session resumption.
/// Session tickets are provided by the server during TLS handshake
/// and can be reused for subsequent connections.
#[derive(Debug, Clone)]
pub struct SessionCache {
    inner: Arc<Mutex<SessionCacheInner>>,
}

#[derive(Debug)]
struct SessionCacheInner {
    /// Session tickets by host:port
    tickets: HashMap<String, SessionTicket>,
    /// Maximum age for session tickets
    max_age: Duration,
}

#[derive(Debug, Clone)]
struct SessionTicket {
    /// Session ticket data (opaque blob from server)
    data: Vec<u8>,
    /// When this ticket was received
    received_at: Instant,
    /// Maximum age for this ticket (from server)
    max_age: Duration,
}

impl SessionCache {
    /// Create a new session cache with default max age (24 hours).
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionCacheInner {
                tickets: HashMap::new(),
                max_age: Duration::from_secs(86400), // 24 hours
            })),
        }
    }

    /// Create a session cache with custom max age.
    pub fn with_max_age(max_age: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionCacheInner {
                tickets: HashMap::new(),
                max_age,
            })),
        }
    }

    /// Store a session ticket for a host.
    pub fn store_ticket(&self, host: &str, ticket_data: Vec<u8>, max_age: Option<Duration>) {
        let mut inner = self.inner.lock().expect("Session cache mutex poisoned");
        let max_age = max_age.unwrap_or(inner.max_age);

        inner.tickets.insert(
            host.to_string(),
            SessionTicket {
                data: ticket_data,
                received_at: Instant::now(),
                max_age,
            },
        );
    }

    /// Get a session ticket for a host (if valid and not expired).
    pub fn get_ticket(&self, host: &str) -> Option<Vec<u8>> {
        let mut inner = self.inner.lock().expect("Session cache mutex poisoned");

        if let Some(ticket) = inner.tickets.get(host) {
            // Check if ticket is still valid
            if ticket.received_at.elapsed() < ticket.max_age {
                return Some(ticket.data.clone());
            } else {
                // Expired, remove it
                inner.tickets.remove(host);
            }
        }

        None
    }

    /// Clear all cached tickets.
    pub fn clear(&self) {
        let mut inner = self.inner.lock().expect("Session cache mutex poisoned");
        inner.tickets.clear();
    }

    /// Remove expired tickets.
    pub fn cleanup_expired(&self) {
        let mut inner = self.inner.lock().expect("Session cache mutex poisoned");
        inner
            .tickets
            .retain(|_, ticket| ticket.received_at.elapsed() < ticket.max_age);
    }

    /// Get the number of cached tickets.
    pub fn len(&self) -> usize {
        let inner = self.inner.lock().expect("Session cache mutex poisoned");
        inner.tickets.len()
    }

    /// Check if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SessionCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_cache_store_and_retrieve() {
        let cache = SessionCache::new();
        cache.store_ticket("example.com", vec![1, 2, 3], None);

        assert_eq!(cache.get_ticket("example.com"), Some(vec![1, 2, 3]));
        assert_eq!(cache.get_ticket("other.com"), None);
    }

    #[test]
    fn test_session_cache_expiration() {
        let cache = SessionCache::with_max_age(Duration::from_secs(1));
        cache.store_ticket("example.com", vec![1, 2, 3], None);

        assert_eq!(cache.get_ticket("example.com"), Some(vec![1, 2, 3]));

        // Wait for expiration
        std::thread::sleep(Duration::from_secs(2));

        // Ticket should be expired
        assert_eq!(cache.get_ticket("example.com"), None);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_session_cache_clear() {
        let cache = SessionCache::new();
        cache.store_ticket("example.com", vec![1, 2, 3], None);
        cache.store_ticket("other.com", vec![4, 5, 6], None);

        assert_eq!(cache.len(), 2);
        cache.clear();
        assert_eq!(cache.len(), 0);
    }
}
