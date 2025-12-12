use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Track TCP connections for testing purposes.
#[derive(Clone)]
#[allow(dead_code)]
pub struct ConnectionTracker {
    connections: Arc<Mutex<HashMap<SocketAddr, Vec<Instant>>>>,
}

#[allow(dead_code)]
impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Record a connection to a given address.
    pub fn record_connection(&self, addr: SocketAddr) {
        let mut conns = self.connections.lock().unwrap();
        conns
            .entry(addr)
            .or_insert_with(Vec::new)
            .push(Instant::now());
    }

    /// Get the number of unique connections to an address.
    pub fn connection_count(&self, addr: SocketAddr) -> usize {
        self.connections
            .lock()
            .unwrap()
            .get(&addr)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Get all connection timestamps for an address.
    pub fn connection_times(&self, addr: SocketAddr) -> Vec<Instant> {
        self.connections
            .lock()
            .unwrap()
            .get(&addr)
            .cloned()
            .unwrap_or_default()
    }

    /// Clear all tracked connections.
    pub fn clear(&self) {
        self.connections.lock().unwrap().clear();
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}
