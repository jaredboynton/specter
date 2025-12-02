//! TLS fingerprint configuration (JA3/JA4).
//!
//! To be implemented: cipher suite ordering, extension ordering, GREASE.

/// TLS fingerprint configuration.
#[derive(Debug, Clone)]
pub struct TlsFingerprint {
    /// Cipher suites in order.
    pub cipher_list: Vec<&'static str>,
    /// Signature algorithms.
    pub sigalgs: Vec<&'static str>,
    /// Supported curves/groups.
    pub curves: Vec<&'static str>,
    /// TLS extensions.
    pub extensions: Vec<u16>,
    /// Extension order (for JA3 fingerprint).
    pub extension_order: Vec<u16>,
    /// Enable GREASE values.
    pub grease: bool,
}

impl Default for TlsFingerprint {
    fn default() -> Self {
        Self {
            cipher_list: vec![],
            sigalgs: vec![],
            curves: vec![],
            extensions: vec![],
            extension_order: vec![],
            grease: true,
        }
    }
}
