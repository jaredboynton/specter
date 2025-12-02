//! TLS fingerprint configuration (JA3/JA4).
//!
//! To be implemented: cipher suite ordering, extension ordering, GREASE.

/// Chrome 131 cipher suites in exact order.
pub const CHROME_131_CIPHER_SUITES: &[&'static str] = &[
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
];

/// Chrome 131 signature algorithms.
pub const CHROME_131_SIGNATURE_ALGORITHMS: &[&'static str] = &[
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
];

/// Chrome 131 supported curves.
pub const CHROME_131_CURVES: &[&'static str] = &["x25519", "P-256", "P-384"];

/// Chrome 131 extension IDs in exact order.
pub const CHROME_131_EXTENSION_IDS: &[u16] =
    &[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21];

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

impl TlsFingerprint {
    /// Create a TLS fingerprint for Chrome 131.
    pub fn chrome_131() -> Self {
        Self {
            cipher_list: CHROME_131_CIPHER_SUITES.to_vec(),
            sigalgs: CHROME_131_SIGNATURE_ALGORITHMS.to_vec(),
            curves: CHROME_131_CURVES.to_vec(),
            extensions: CHROME_131_EXTENSION_IDS.to_vec(),
            extension_order: CHROME_131_EXTENSION_IDS.to_vec(),
            grease: true,
        }
    }
}
