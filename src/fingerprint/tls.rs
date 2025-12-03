//! TLS fingerprint configuration for browser impersonation.
//!
//! WARNING: Chrome randomizes TLS extension order since v110, making static
//! JA3 fingerprints unreliable. Modern fingerprint detection systems use JA4 which sorts
//! extensions alphabetically. This implementation provides cipher suite,
//! signature algorithm, and curve ordering - but extension ordering may not
//! match real browsers.
//!
//! Current implementation: Chrome 142 (Dec 2025)

/// Chrome 142 cipher suites in exact order.
pub const CHROME_142_CIPHER_SUITES: &[&str] = &[
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

/// Chrome 142 signature algorithms.
pub const CHROME_142_SIGNATURE_ALGORITHMS: &[&str] = &[
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
];

/// Chrome 142 supported curves.
pub const CHROME_142_CURVES: &[&str] = &["x25519", "P-256", "P-384"];

/// Chrome 142 extension IDs in exact order.
pub const CHROME_142_EXTENSION_IDS: &[u16] =
    &[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21];

/// Firefox 133 cipher suites in exact order.
/// Firefox prefers AES-GCM over ChaCha20 (unlike some mobile-optimized builds).
pub const FIREFOX_133_CIPHER_SUITES: &[&str] = &[
    // TLS 1.3 cipher suites
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    // TLS 1.2 ECDHE cipher suites
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    // Legacy TLS 1.2 cipher suites
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
];

/// Firefox 133 signature algorithms.
/// Similar to Chrome but may have slight ordering differences.
pub const FIREFOX_133_SIGNATURE_ALGORITHMS: &[&str] = &[
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
];

/// Firefox 133 supported curves.
/// Firefox supports more curves than Chrome, including P-521.
/// Note: BoringSSL uses "P-256", "P-384", "P-521" (not secp256r1/secp384r1/secp521r1)
pub const FIREFOX_133_CURVES: &[&str] = &["x25519", "P-256", "P-384", "P-521"];

/// Firefox 133 extension IDs.
/// Note: Firefox 133 also randomizes extension order (like Chrome 110+),
/// so JA3 fingerprints will vary. JA4 sorts extensions for stable fingerprinting.
pub const FIREFOX_133_EXTENSION_IDS: &[u16] =
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
    /// Create a TLS fingerprint for Chrome 142.
    pub fn chrome_142() -> Self {
        Self {
            cipher_list: CHROME_142_CIPHER_SUITES.to_vec(),
            sigalgs: CHROME_142_SIGNATURE_ALGORITHMS.to_vec(),
            curves: CHROME_142_CURVES.to_vec(),
            extensions: CHROME_142_EXTENSION_IDS.to_vec(),
            extension_order: CHROME_142_EXTENSION_IDS.to_vec(),
            grease: true,
        }
    }

    /// Create a TLS fingerprint for Firefox 133.
    ///
    /// Firefox differs from Chrome in:
    /// - Cipher suite order (AES-GCM preferred, ChaCha20 third)
    /// - More curves supported (includes P-521)
    /// - No GREASE values (Firefox doesn't use GREASE)
    /// - Extension order randomization (like Chrome 110+)
    pub fn firefox_133() -> Self {
        Self {
            cipher_list: FIREFOX_133_CIPHER_SUITES.to_vec(),
            sigalgs: FIREFOX_133_SIGNATURE_ALGORITHMS.to_vec(),
            curves: FIREFOX_133_CURVES.to_vec(),
            extensions: FIREFOX_133_EXTENSION_IDS.to_vec(),
            extension_order: FIREFOX_133_EXTENSION_IDS.to_vec(),
            grease: false, // Firefox does NOT use GREASE
        }
    }
}
