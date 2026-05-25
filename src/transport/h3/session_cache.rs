//! Native HTTP/3 TLS session cache.
//!
//! Stores DER-encoded TLS 1.3 [`SSL_SESSION`] tickets captured via
//! BoringSSL's `SSL_CTX_sess_set_new_cb` so the next connect to the same
//! peer can call `SSL_set_session` and attempt resumption (RFC 8446
//! section 2.2 / section 4.6.1). The cache also remembers the
//! `max_early_data` advertised by the ticket so the caller can decide
//! whether to offer 0-RTT for the next connection (RFC 9001 section 4.6).
//!
//! ## Key shape
//!
//! Entries are keyed by:
//! - SNI (server hostname the original handshake used),
//! - ALPN protocol list (so an h3 ticket is never replayed against an h2-only stack),
//! - peer-verification mode (a ticket built under `verify_peer = true` must
//!   not be replayed under `verify_peer = false` and vice versa - the
//!   master secret would be the same, but the binding context is not),
//! - an optional fingerprint-pin string (`TlsFingerprint::pool_key_string`
//!   or any other stable representation). When set, switching the
//!   ClientHello shape - cipher list / extensions / curves / sigalgs /
//!   cert compression / GREASE / Kyber - moves the entry to a different
//!   cache row so the replay cannot emit a ClientHello that disagrees
//!   with the shape under which the ticket was issued. Per RFC 8446
//!   section 4.2.11, the PSK binder depends on the chosen ClientHello,
//!   so a mismatched fingerprint must not reuse the same ticket.
//!
//! ## Anti-replay
//!
//! Tickets are advisory: BoringSSL still enforces ticket lifetime,
//! `obfuscated_ticket_age`, and `quic_early_data_context` byte-equality
//! checks during the handshake (RFC 9001 section 4.6.1). This cache only
//! reduces the chance that the wrong ticket is offered; the actual
//! 0-RTT acceptance/rejection decision is made by the server and
//! surfaced via `NativeQuicTlsSession::handshake_status`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;

/// Cache-row coordinates for a native H3 TLS session ticket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NativeH3SessionCacheKey {
    /// Server SNI used on the handshake that produced this ticket.
    pub sni: String,
    /// ALPN protocol list (each element is a wire-form ALPN identifier
    /// such as `b"h3"`). Ordering is preserved; two clients that
    /// advertise different ALPN orderings cache separately.
    pub alpn: Vec<Vec<u8>>,
    /// Whether the original handshake validated the peer certificate.
    /// A ticket captured with `verify_peer = false` is never replayed
    /// with `verify_peer = true`.
    pub verify_peer: bool,
    /// Optional fingerprint-pin string. When `Some`, switching the
    /// ClientHello shape (cipher list / extension order / curves /
    /// sigalgs / cert compression / GREASE / Kyber) moves to a
    /// different row so the replay cannot emit an inconsistent
    /// ClientHello relative to the original handshake. When `None`,
    /// the entry matches any fingerprint that shares the other key
    /// components - useful when the caller is intentionally letting
    /// BoringSSL decide everything.
    pub fingerprint_pin: Option<String>,
}

impl NativeH3SessionCacheKey {
    pub fn new(
        sni: impl Into<String>,
        alpn: impl IntoIterator<Item = Vec<u8>>,
        verify_peer: bool,
        fingerprint_pin: Option<String>,
    ) -> Self {
        Self {
            sni: sni.into(),
            alpn: alpn.into_iter().collect(),
            verify_peer,
            fingerprint_pin,
        }
    }
}

/// A single cache entry: the DER-encoded session and the early-data hint
/// at capture time. `received_at` + `lifetime` is honored independently
/// of BoringSSL's own ticket-age check so callers can bound replay
/// windows below the server-issued ticket lifetime (RFC 9001 section
/// 9.2: 0-RTT anti-replay requires the caller to mark requests
/// idempotent and the cache to bound replay attempts).
#[derive(Debug, Clone)]
pub struct NativeH3SessionEntry {
    pub der: Bytes,
    pub max_early_data: u32,
    pub received_at: Instant,
    pub lifetime: Duration,
}

impl NativeH3SessionEntry {
    pub fn new(der: Bytes, max_early_data: u32, lifetime: Duration) -> Self {
        Self {
            der,
            max_early_data,
            received_at: Instant::now(),
            lifetime,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.received_at.elapsed() >= self.lifetime
    }

    pub fn supports_zero_rtt(&self) -> bool {
        self.max_early_data > 0 && !self.is_expired()
    }
}

/// Thread-safe in-memory store of native H3 TLS session tickets.
#[derive(Debug, Clone)]
pub struct NativeH3SessionCache {
    inner: Arc<Mutex<NativeH3SessionCacheInner>>,
}

#[derive(Debug)]
struct NativeH3SessionCacheInner {
    entries: HashMap<NativeH3SessionCacheKey, NativeH3SessionEntry>,
    default_lifetime: Duration,
    max_entries: usize,
}

const DEFAULT_LIFETIME_SECS: u64 = 6 * 3600;
const DEFAULT_MAX_ENTRIES: usize = 256;

impl NativeH3SessionCache {
    pub fn new() -> Self {
        Self::with_capacity(
            DEFAULT_MAX_ENTRIES,
            Duration::from_secs(DEFAULT_LIFETIME_SECS),
        )
    }

    pub fn with_capacity(max_entries: usize, default_lifetime: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(NativeH3SessionCacheInner {
                entries: HashMap::new(),
                default_lifetime,
                max_entries: max_entries.max(1),
            })),
        }
    }

    /// Insert (or overwrite) a session ticket. `lifetime` of `None` falls
    /// back to the cache-level default. The provided `max_early_data`
    /// must come from the captured `SSL_SESSION` (e.g. via
    /// `SslSessionRef::max_early_data` or the legacy
    /// `SSL_SESSION_get_max_early_data` FFI). Pass `0` to record a
    /// ticket that the server did not authorize for 0-RTT.
    pub fn insert(
        &self,
        key: NativeH3SessionCacheKey,
        der: impl Into<Bytes>,
        max_early_data: u32,
        lifetime: Option<Duration>,
    ) {
        let mut inner = self.inner.lock().expect("native H3 session cache poisoned");
        let lifetime = lifetime.unwrap_or(inner.default_lifetime);
        if inner.entries.len() >= inner.max_entries && !inner.entries.contains_key(&key) {
            // Bound memory by evicting the oldest expired entry first,
            // then the oldest healthy entry as a last resort.
            let oldest_expired = inner
                .entries
                .iter()
                .filter(|(_, entry)| entry.is_expired())
                .min_by_key(|(_, entry)| entry.received_at)
                .map(|(k, _)| k.clone());
            if let Some(stale) = oldest_expired {
                inner.entries.remove(&stale);
            } else if let Some(oldest) = inner
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.received_at)
                .map(|(k, _)| k.clone())
            {
                inner.entries.remove(&oldest);
            }
        }
        inner.entries.insert(
            key,
            NativeH3SessionEntry::new(der.into(), max_early_data, lifetime),
        );
    }

    /// Look up a session ticket. Expired tickets are removed from the
    /// cache as a side effect so subsequent calls do not return them.
    pub fn get(&self, key: &NativeH3SessionCacheKey) -> Option<NativeH3SessionEntry> {
        let mut inner = self.inner.lock().expect("native H3 session cache poisoned");
        match inner.entries.get(key) {
            Some(entry) if !entry.is_expired() => Some(entry.clone()),
            Some(_) => {
                inner.entries.remove(key);
                None
            }
            None => None,
        }
    }

    /// Remove a single entry without consulting it.
    pub fn evict(&self, key: &NativeH3SessionCacheKey) {
        let mut inner = self.inner.lock().expect("native H3 session cache poisoned");
        inner.entries.remove(key);
    }

    /// Drop all expired entries.
    pub fn purge_expired(&self) {
        let mut inner = self.inner.lock().expect("native H3 session cache poisoned");
        inner.entries.retain(|_, entry| !entry.is_expired());
    }

    /// Drop every entry (e.g. when a TLS configuration change invalidates the cache).
    pub fn clear(&self) {
        let mut inner = self.inner.lock().expect("native H3 session cache poisoned");
        inner.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("native H3 session cache poisoned")
            .entries
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for NativeH3SessionCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(
        sni: &str,
        alpn: &[&[u8]],
        verify_peer: bool,
        pin: Option<&str>,
    ) -> NativeH3SessionCacheKey {
        NativeH3SessionCacheKey::new(
            sni,
            alpn.iter().map(|p| p.to_vec()),
            verify_peer,
            pin.map(|s| s.to_string()),
        )
    }

    #[test]
    fn insert_get_round_trip() {
        let cache = NativeH3SessionCache::new();
        let k = key("example.com", &[b"h3"], true, Some("chrome"));
        cache.insert(k.clone(), Bytes::from_static(b"der-bytes"), 16_384, None);

        let entry = cache.get(&k).expect("entry present");
        assert_eq!(entry.der.as_ref(), b"der-bytes");
        assert_eq!(entry.max_early_data, 16_384);
        assert!(entry.supports_zero_rtt());
    }

    #[test]
    fn fingerprint_pin_isolates_entries() {
        let cache = NativeH3SessionCache::new();
        let chrome_key = key("example.com", &[b"h3"], true, Some("chrome"));
        let firefox_key = key("example.com", &[b"h3"], true, Some("firefox"));
        cache.insert(
            chrome_key.clone(),
            Bytes::from_static(b"chrome-der"),
            0,
            None,
        );
        assert!(cache.get(&firefox_key).is_none());
        assert!(cache.get(&chrome_key).is_some());
    }

    #[test]
    fn verify_peer_dimension_isolates_entries() {
        let cache = NativeH3SessionCache::new();
        let strict = key("example.com", &[b"h3"], true, None);
        let relaxed = key("example.com", &[b"h3"], false, None);
        cache.insert(strict.clone(), Bytes::from_static(b"strict"), 0, None);
        cache.insert(relaxed.clone(), Bytes::from_static(b"relaxed"), 0, None);
        assert_eq!(cache.get(&strict).unwrap().der.as_ref(), b"strict");
        assert_eq!(cache.get(&relaxed).unwrap().der.as_ref(), b"relaxed");
    }

    #[test]
    fn alpn_dimension_isolates_entries() {
        let cache = NativeH3SessionCache::new();
        let h3 = key("example.com", &[b"h3"], true, None);
        let h2 = key("example.com", &[b"h2"], true, None);
        cache.insert(h3.clone(), Bytes::from_static(b"h3"), 0, None);
        assert!(cache.get(&h2).is_none());
        assert_eq!(cache.get(&h3).unwrap().der.as_ref(), b"h3");
    }

    #[test]
    fn expired_entries_are_evicted_on_lookup() {
        let cache = NativeH3SessionCache::with_capacity(8, Duration::from_millis(50));
        let k = key("example.com", &[b"h3"], true, None);
        cache.insert(k.clone(), Bytes::from_static(b"short-lived"), 0, None);
        std::thread::sleep(Duration::from_millis(80));
        assert!(cache.get(&k).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn capacity_bound_evicts_oldest_entry() {
        let cache = NativeH3SessionCache::with_capacity(2, Duration::from_secs(60));
        let a = key("a", &[b"h3"], true, None);
        let b = key("b", &[b"h3"], true, None);
        let c = key("c", &[b"h3"], true, None);
        cache.insert(a.clone(), Bytes::from_static(b"a"), 0, None);
        std::thread::sleep(Duration::from_millis(5));
        cache.insert(b.clone(), Bytes::from_static(b"b"), 0, None);
        std::thread::sleep(Duration::from_millis(5));
        cache.insert(c.clone(), Bytes::from_static(b"c"), 0, None);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&a).is_none(), "oldest entry should be evicted");
        assert!(cache.get(&b).is_some());
        assert!(cache.get(&c).is_some());
    }
}
