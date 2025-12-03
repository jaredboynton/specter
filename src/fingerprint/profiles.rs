//! Browser fingerprint profiles.

use super::http2::Http2Settings;
use super::tls::TlsFingerprint;

/// Browser fingerprint profile for impersonation.
///
/// Note: Both Chrome 110+ and Firefox 133+ randomize TLS extension order,
/// making static JA3 fingerprints unreliable. Modern fingerprint detection
/// systems use JA4 which sorts extensions alphabetically for stable fingerprints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FingerprintProfile {
    /// Chrome 142 on macOS - basic fingerprint (cipher suites, curves, sigalgs)
    /// TLS extension order is randomized by Chrome, so this fingerprint
    /// will not match real Chrome exactly.
    #[default]
    Chrome142,
    /// Firefox 133 on macOS - basic fingerprint (cipher suites, curves, sigalgs)
    /// TLS extension order is randomized by Firefox, so this fingerprint
    /// will not match real Firefox exactly. Firefox does NOT use GREASE.
    Firefox133,
    /// No fingerprinting - use default TLS settings
    None,
}

impl FingerprintProfile {
    /// Get the User-Agent string for this profile.
    pub fn user_agent(&self) -> &'static str {
        match self {
            Self::Chrome142 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
            }
            Self::Firefox133 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0"
            }
            Self::None => "specter/0.1",
        }
    }

    /// Get the TLS fingerprint for this profile.
    pub fn tls_fingerprint(&self) -> TlsFingerprint {
        match self {
            FingerprintProfile::Chrome142 => TlsFingerprint::chrome_142(),
            FingerprintProfile::Firefox133 => TlsFingerprint::firefox_133(),
            FingerprintProfile::None => TlsFingerprint::default(),
        }
    }

    /// Get the HTTP/2 settings for this profile.
    pub fn http2_settings(&self) -> Http2Settings {
        match self {
            FingerprintProfile::Chrome142 => Http2Settings::default(),
            FingerprintProfile::Firefox133 => Http2Settings::firefox(),
            FingerprintProfile::None => Http2Settings::default(),
        }
    }
}
