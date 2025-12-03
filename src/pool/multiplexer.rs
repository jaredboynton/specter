//! Connection pool for HTTP/2 and HTTP/3 multiplexing
//!
//! This module provides connection pooling with support for:
//! - HTTP/1.1: One connection per request (no pooling)
//! - HTTP/2: Connection reuse with stream multiplexing
//! - HTTP/3: QUIC connection reuse with stream multiplexing

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::error::Result;
use crate::version::HttpVersion;

/// Connection pool key identifying a unique host/port combination
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct PoolKey {
    pub host: String,
    pub port: u16,
    pub is_https: bool,
}

impl PoolKey {
    /// Create a new pool key
    pub fn new(host: String, port: u16, is_https: bool) -> Self {
        Self {
            host,
            port,
            is_https,
        }
    }
}

/// Pool entry tracking connection state and stream usage
#[derive(Debug, Clone)]
pub struct PoolEntry {
    pub version: HttpVersion,
    pub established_at: Instant,
    pub last_used: Instant,
    /// Number of active streams (for HTTP/2 and HTTP/3)
    pub active_streams: u32,
    /// Maximum concurrent streams (from SETTINGS for HTTP/2)
    pub max_streams: u32,
    /// Connection is still valid
    pub is_valid: bool,
}

impl PoolEntry {
    /// Create a new pool entry
    pub fn new(version: HttpVersion, max_streams: u32) -> Self {
        let now = Instant::now();
        Self {
            version,
            established_at: now,
            last_used: now,
            active_streams: 0,
            max_streams,
            is_valid: true,
        }
    }

    /// Check if this connection can handle another multiplexed stream
    pub fn can_multiplex(&self) -> bool {
        matches!(
            self.version,
            HttpVersion::Http2 | HttpVersion::Http3 | HttpVersion::Http3Only
        ) && self.active_streams < self.max_streams
            && self.is_valid
    }

    /// Attempt to acquire a stream slot
    pub fn acquire_stream(&mut self) -> bool {
        if self.can_multiplex() {
            self.active_streams += 1;
            self.last_used = Instant::now();
            true
        } else {
            false
        }
    }

    /// Release a stream slot
    pub fn release_stream(&mut self) {
        if self.active_streams > 0 {
            self.active_streams -= 1;
            self.last_used = Instant::now();
        }
    }

    /// Mark connection as invalid (connection error, GOAWAY frame, etc.)
    pub fn invalidate(&mut self) {
        self.is_valid = false;
    }

    /// Check if connection is expired based on idle time
    pub fn is_expired(&self, max_idle: Duration) -> bool {
        let age = Instant::now().duration_since(self.last_used);
        age >= max_idle
    }
}

/// Connection pool for reusing HTTP/2 and HTTP/3 connections
pub struct ConnectionPool {
    entries: Arc<RwLock<HashMap<PoolKey, PoolEntry>>>,
    max_idle_duration: Duration,
    #[allow(dead_code)] // Reserved for future connection limiting per host
    max_connections_per_host: usize,
    default_max_streams: u32,
}

impl ConnectionPool {
    /// Default maximum idle duration (30 seconds)
    const DEFAULT_MAX_IDLE: Duration = Duration::from_secs(30);

    /// Default maximum connections per host
    const DEFAULT_MAX_PER_HOST: usize = 6;

    /// Default maximum concurrent streams for HTTP/2 and HTTP/3
    const DEFAULT_MAX_STREAMS: u32 = 100;

    /// Create a new connection pool with default settings
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_idle_duration: Self::DEFAULT_MAX_IDLE,
            max_connections_per_host: Self::DEFAULT_MAX_PER_HOST,
            default_max_streams: Self::DEFAULT_MAX_STREAMS,
        }
    }

    /// Create a connection pool with custom configuration
    pub fn with_config(max_idle: Duration, max_per_host: usize, max_streams: u32) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_idle_duration: max_idle,
            max_connections_per_host: max_per_host,
            default_max_streams: max_streams,
        }
    }

    /// Get an existing connection or signal that a new one should be created
    ///
    /// Returns:
    /// - `Ok(Some(entry))`: Reusable connection found (HTTP/2 or HTTP/3)
    /// - `Ok(None)`: No reusable connection, create new one
    pub async fn get_or_create(
        &self,
        key: &PoolKey,
        version: HttpVersion,
    ) -> Result<Option<PoolEntry>> {
        let mut entries = self.entries.write().await;

        // HTTP/1.1 doesn't support multiplexing - always create new connection
        if version == HttpVersion::Http1_1 {
            return Ok(None);
        }

        // Check for existing valid connection with available stream slots
        if let Some(entry) = entries.get_mut(key) {
            if entry.acquire_stream() {
                return Ok(Some(entry.clone()));
            }
        }

        // No reusable connection found - create new entry
        let entry = PoolEntry::new(version, self.default_max_streams);
        entries.insert(key.clone(), entry.clone());

        Ok(Some(entry))
    }

    /// Release a stream slot back to the pool
    pub async fn release(&self, key: &PoolKey) {
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get_mut(key) {
            entry.release_stream();
        }
    }

    /// Invalidate a connection (due to error, GOAWAY, etc.)
    pub async fn invalidate(&self, key: &PoolKey) {
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get_mut(key) {
            entry.invalidate();
        }
    }

    /// Remove expired and invalid connections
    pub async fn cleanup(&self) {
        let mut entries = self.entries.write().await;
        entries.retain(|_key, entry| entry.is_valid && !entry.is_expired(self.max_idle_duration));
    }

    /// Spawn a background cleanup task that runs periodically
    ///
    /// Returns a handle to the spawned task
    pub fn spawn_cleanup_task(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                interval_timer.tick().await;
                self.cleanup().await;
            }
        })
    }

    /// Get current pool statistics (for debugging/monitoring)
    pub async fn stats(&self) -> PoolStats {
        let entries = self.entries.read().await;
        PoolStats {
            total_connections: entries.len(),
            active_streams: entries.values().map(|e| e.active_streams).sum(),
            http2_connections: entries
                .values()
                .filter(|e| matches!(e.version, HttpVersion::Http2))
                .count(),
            http3_connections: entries
                .values()
                .filter(|e| matches!(e.version, HttpVersion::Http3 | HttpVersion::Http3Only))
                .count(),
        }
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Pool statistics for monitoring
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: usize,
    pub active_streams: u32,
    pub http2_connections: usize,
    pub http3_connections: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_key_equality() {
        let key1 = PoolKey::new("example.com".to_string(), 443, true);
        let key2 = PoolKey::new("example.com".to_string(), 443, true);
        let key3 = PoolKey::new("example.com".to_string(), 80, false);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_pool_entry_multiplexing() {
        let mut entry = PoolEntry::new(HttpVersion::Http2, 100);

        // Should be able to acquire streams
        assert!(entry.can_multiplex());
        assert!(entry.acquire_stream());
        assert_eq!(entry.active_streams, 1);

        // Release stream
        entry.release_stream();
        assert_eq!(entry.active_streams, 0);
    }

    #[test]
    fn test_pool_entry_max_streams() {
        let mut entry = PoolEntry::new(HttpVersion::Http2, 2);

        assert!(entry.acquire_stream());
        assert!(entry.acquire_stream());
        assert!(!entry.acquire_stream()); // Max reached
        assert_eq!(entry.active_streams, 2);
    }

    #[test]
    fn test_pool_entry_invalidation() {
        let mut entry = PoolEntry::new(HttpVersion::Http2, 100);

        assert!(entry.can_multiplex());
        entry.invalidate();
        assert!(!entry.can_multiplex());
    }

    #[test]
    fn test_pool_entry_expiration() {
        let entry = PoolEntry::new(HttpVersion::Http2, 100);

        // Should not be expired immediately
        assert!(!entry.is_expired(Duration::from_secs(30)));

        // Test with zero duration (always expired)
        assert!(entry.is_expired(Duration::from_secs(0)));
    }

    #[tokio::test]
    async fn test_connection_pool_http11() {
        let pool = ConnectionPool::new();
        let key = PoolKey::new("example.com".to_string(), 443, true);

        // HTTP/1.1 should always return None (no pooling)
        let result = pool
            .get_or_create(&key, HttpVersion::Http1_1)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_connection_pool_http2_multiplexing() {
        let pool = ConnectionPool::new();
        let key = PoolKey::new("example.com".to_string(), 443, true);

        // First request creates connection
        let entry1 = pool.get_or_create(&key, HttpVersion::Http2).await.unwrap();
        assert!(entry1.is_some());

        // Second request should reuse connection
        let entry2 = pool.get_or_create(&key, HttpVersion::Http2).await.unwrap();
        assert!(entry2.is_some());

        // Verify stats
        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.http2_connections, 1);
    }

    #[tokio::test]
    async fn test_connection_pool_release() {
        let pool = ConnectionPool::new();
        let key = PoolKey::new("example.com".to_string(), 443, true);

        let _entry = pool.get_or_create(&key, HttpVersion::Http2).await.unwrap();

        // Release stream
        pool.release(&key).await;

        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 1);
    }

    #[tokio::test]
    async fn test_connection_pool_invalidation() {
        let pool = ConnectionPool::new();
        let key = PoolKey::new("example.com".to_string(), 443, true);

        let _entry = pool.get_or_create(&key, HttpVersion::Http2).await.unwrap();

        // Invalidate connection
        pool.invalidate(&key).await;

        // Cleanup should remove invalid connection
        pool.cleanup().await;

        let stats = pool.stats().await;
        assert_eq!(stats.total_connections, 0);
    }
}
