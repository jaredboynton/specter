//! Browser fingerprint profiles.

use super::tls::TlsFingerprint;

/// Browser fingerprint profile for impersonation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FingerprintProfile {
    /// Chrome 131 on macOS
    #[default]
    Chrome131,
    /// Chrome 130 on macOS
    Chrome130,
    /// Firefox 133 on macOS
    Firefox133,
    /// Safari 18 on macOS
    Safari18,
    /// No fingerprinting - use default TLS settings
    None,
}

impl FingerprintProfile {
    /// Get the User-Agent string for this profile.
    pub fn user_agent(&self) -> &'static str {
        match self {
            Self::Chrome131 | Self::Chrome130 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            }
            Self::Firefox133 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0"
            }
            Self::Safari18 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
            }
            Self::None => "specter/0.1",
        }
    }

    /// Get the TLS fingerprint for this profile.
    pub fn tls_fingerprint(&self) -> TlsFingerprint {
        match self {
            FingerprintProfile::Chrome131 => TlsFingerprint::chrome_131(),
            FingerprintProfile::Chrome130 => TlsFingerprint::default(),
            FingerprintProfile::Firefox133 => TlsFingerprint::default(),
            FingerprintProfile::Safari18 => TlsFingerprint::default(),
            FingerprintProfile::None => TlsFingerprint::default(),
        }
    }
}
