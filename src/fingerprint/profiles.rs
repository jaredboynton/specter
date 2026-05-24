//! Browser fingerprint profiles.

use super::http2::Http2Settings;
use super::http3::Http3Fingerprint;
use super::tls::TlsFingerprint;
use crate::transport::h2::PseudoHeaderOrder;

/// Browser fingerprint profile for impersonation.
///
/// Both Chrome 110+ and Firefox 133+ randomize TLS extension order,
/// making static JA3 fingerprints unreliable. Modern fingerprint detection
/// systems use JA4 which sorts extensions alphabetically for stable fingerprints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FingerprintProfile {
    /// Chrome 142 on macOS
    #[default]
    Chrome142,
    /// Chrome 143 on macOS
    Chrome143,
    /// Chrome 144 on macOS
    Chrome144,
    /// Chrome 145 on macOS
    Chrome145,
    /// Chrome 146 on macOS
    Chrome146,
    /// Chrome 147 on macOS
    Chrome147,
    /// Chrome 148 on macOS
    Chrome148,
    /// Firefox 133 on macOS - basic fingerprint (cipher suites, curves, sigalgs)
    /// TLS extension order is randomized by Firefox, so this fingerprint
    /// will not match real Firefox exactly. Firefox does NOT use GREASE.
    Firefox133,
    /// No fingerprinting - use default TLS settings
    None,
    /// Firefox 134 on macOS
    Firefox134,
    /// Firefox 135 on macOS
    Firefox135,
    /// Firefox 136 on macOS
    Firefox136,
    /// Firefox 137 on macOS
    Firefox137,
    /// Firefox 138 on macOS
    Firefox138,
    /// Firefox 139 on macOS
    Firefox139,
    /// Firefox 140 on macOS
    Firefox140,
    /// Firefox 141 on macOS
    Firefox141,
    /// Firefox 142 on macOS
    Firefox142,
    /// Firefox 143 on macOS
    Firefox143,
    /// Firefox 144 on macOS
    Firefox144,
    /// Firefox 145 on macOS
    Firefox145,
    /// Firefox 146 on macOS
    Firefox146,
    /// Firefox 147 on macOS
    Firefox147,
    /// Firefox 148 on macOS
    Firefox148,
    /// Firefox 149 on macOS
    Firefox149,
    /// Firefox 150 on macOS
    Firefox150,
    /// Firefox 151 on macOS
    Firefox151,
    /// Firefox 115 ESR on legacy macOS
    FirefoxEsr115,
    /// Firefox 128 ESR on macOS
    FirefoxEsr128,
    /// Firefox 140 ESR on macOS
    FirefoxEsr140,
}

impl FingerprintProfile {
    /// Whether this profile represents a Firefox release or ESR line.
    pub fn is_firefox(&self) -> bool {
        matches!(
            self,
            Self::Firefox133
                | Self::Firefox134
                | Self::Firefox135
                | Self::Firefox136
                | Self::Firefox137
                | Self::Firefox138
                | Self::Firefox139
                | Self::Firefox140
                | Self::Firefox141
                | Self::Firefox142
                | Self::Firefox143
                | Self::Firefox144
                | Self::Firefox145
                | Self::Firefox146
                | Self::Firefox147
                | Self::Firefox148
                | Self::Firefox149
                | Self::Firefox150
                | Self::Firefox151
                | Self::FirefoxEsr115
                | Self::FirefoxEsr128
                | Self::FirefoxEsr140
        )
    }

    /// Get the User-Agent string for this profile.
    pub fn user_agent(&self) -> &'static str {
        match self {
            Self::Chrome142 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
            }
            Self::Chrome143 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
            }
            Self::Chrome144 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
            }
            Self::Chrome145 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
            }
            Self::Chrome146 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
            }
            Self::Chrome147 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
            }
            Self::Chrome148 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
            }
            Self::Firefox133 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0"
            }
            Self::None => "specter/0.1",
            Self::Firefox134 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:134.0) Gecko/20100101 Firefox/134.0"
            }
            Self::Firefox135 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0"
            }
            Self::Firefox136 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0"
            }
            Self::Firefox137 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0"
            }
            Self::Firefox138 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0"
            }
            Self::Firefox139 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:139.0) Gecko/20100101 Firefox/139.0"
            }
            Self::Firefox140 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0"
            }
            Self::Firefox141 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0"
            }
            Self::Firefox142 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0"
            }
            Self::Firefox143 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0"
            }
            Self::Firefox144 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0"
            }
            Self::Firefox145 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:145.0) Gecko/20100101 Firefox/145.0"
            }
            Self::Firefox146 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0"
            }
            Self::Firefox147 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0"
            }
            Self::Firefox148 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0"
            }
            Self::Firefox149 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0"
            }
            Self::Firefox150 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:150.0) Gecko/20100101 Firefox/150.0"
            }
            Self::Firefox151 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:151.0) Gecko/20100101 Firefox/151.0"
            }
            Self::FirefoxEsr115 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:115.0) Gecko/20100101 Firefox/115.0"
            }
            Self::FirefoxEsr128 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0"
            }
            Self::FirefoxEsr140 => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0"
            }
        }
    }

    /// Get the TLS fingerprint for this profile.
    pub fn tls_fingerprint(&self) -> TlsFingerprint {
        if self.is_firefox() {
            TlsFingerprint::firefox()
        } else {
            match self {
                FingerprintProfile::Chrome142
                | FingerprintProfile::Chrome143
                | FingerprintProfile::Chrome144
                | FingerprintProfile::Chrome145
                | FingerprintProfile::Chrome146
                | FingerprintProfile::Chrome147
                | FingerprintProfile::Chrome148 => TlsFingerprint::chrome(),
                FingerprintProfile::None => TlsFingerprint::default(),
                _ => unreachable!("all Firefox profiles are handled above"),
            }
        }
    }

    /// Get the HTTP/2 settings for this profile.
    pub fn http2_settings(&self) -> Http2Settings {
        if self.is_firefox() {
            Http2Settings::firefox()
        } else {
            Http2Settings::default()
        }
    }

    /// Get the HTTP/2 pseudo-header order for this profile.
    pub fn http2_pseudo_order(&self) -> PseudoHeaderOrder {
        if self.is_firefox() {
            PseudoHeaderOrder::Firefox
        } else {
            PseudoHeaderOrder::Chrome
        }
    }

    /// Get the HTTP/3 and QUIC fingerprint for this profile.
    pub fn http3_fingerprint(&self) -> Http3Fingerprint {
        if self.is_firefox() {
            Http3Fingerprint::firefox()
        } else {
            match self {
                FingerprintProfile::Chrome142
                | FingerprintProfile::Chrome143
                | FingerprintProfile::Chrome144
                | FingerprintProfile::Chrome145
                | FingerprintProfile::Chrome146
                | FingerprintProfile::Chrome147
                | FingerprintProfile::Chrome148 => Http3Fingerprint::chrome(),
                FingerprintProfile::None => Http3Fingerprint::default(),
                _ => unreachable!("all Firefox profiles are handled above"),
            }
        }
    }
}
