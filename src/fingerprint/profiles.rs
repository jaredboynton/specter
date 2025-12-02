//! Browser fingerprint profiles.

use super::tls::TlsFingerprint;

/// Browser fingerprint profile for impersonation.
/// 
/// Note: Chrome randomizes TLS extension order since v110, making static
/// fingerprints detectable. Consider using JA4 fingerprinting which handles
/// this by sorting extensions alphabetically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FingerprintProfile {
    /// Chrome 131 on macOS - basic fingerprint (cipher suites, curves, sigalgs)
    /// WARNING: This is outdated. Chrome 142 is current as of Dec 2025.
    /// TLS extension order is randomized by Chrome, so this fingerprint
    /// will not match real Chrome exactly.
    #[default]
    Chrome131,
    /// No fingerprinting - use default TLS settings
    None,
}

impl FingerprintProfile {
    /// Get the User-Agent string for this profile.
    pub fn user_agent(&self) -> &'static str {
        match self {
            Self::Chrome131 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            }
            Self::None => "specter/0.1",
        }
    }

    /// Get the TLS fingerprint for this profile.
    pub fn tls_fingerprint(&self) -> TlsFingerprint {
        match self {
            FingerprintProfile::Chrome131 => TlsFingerprint::chrome_131(),
            FingerprintProfile::None => TlsFingerprint::default(),
        }
    }
}
