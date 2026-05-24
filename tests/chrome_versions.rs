//! Chrome multi-version fingerprint validation tests.
//!
//! Validates Chrome 142-148 fingerprint profiles produce correct
//! User-Agent strings, Sec-Ch-Ua headers, and shared TLS/HTTP/2/HTTP/3 config.

use specter::fingerprint::profiles::FingerprintProfile;
use specter::fingerprint::tls::{CertCompression, TlsFingerprint};
use specter::fingerprint::Http3Fingerprint;
use specter::headers::{
    chrome_142_ajax_headers, chrome_142_form_headers, chrome_142_headers, chrome_143_ajax_headers,
    chrome_143_form_headers, chrome_143_headers, chrome_144_ajax_headers, chrome_144_form_headers,
    chrome_144_headers, chrome_145_ajax_headers, chrome_145_form_headers, chrome_145_headers,
    chrome_146_ajax_headers, chrome_146_form_headers, chrome_146_headers, chrome_147_ajax_headers,
    chrome_147_form_headers, chrome_147_headers, chrome_148_ajax_headers, chrome_148_form_headers,
    chrome_148_headers,
};

const CHROME_PROFILES: &[(FingerprintProfile, u16)] = &[
    (FingerprintProfile::Chrome142, 142),
    (FingerprintProfile::Chrome143, 143),
    (FingerprintProfile::Chrome144, 144),
    (FingerprintProfile::Chrome145, 145),
    (FingerprintProfile::Chrome146, 146),
    (FingerprintProfile::Chrome147, 147),
    (FingerprintProfile::Chrome148, 148),
];

#[test]
fn test_default_profile_is_chrome142() {
    // Default must remain Chrome142 for SemVer backwards compatibility
    assert_eq!(FingerprintProfile::default(), FingerprintProfile::Chrome142);
}

#[test]
fn test_chrome_user_agents_contain_correct_version() {
    for (profile, major_version) in CHROME_PROFILES {
        let expected_version = format!("Chrome/{major_version}.0.0.0");
        let ua = profile.user_agent();
        assert!(
            ua.contains(&expected_version),
            "Profile {:?} UA should contain '{}', got: {}",
            profile,
            expected_version,
            ua
        );
        // All should be macOS
        assert!(
            ua.contains("Macintosh; Intel Mac OS X 10_15_7"),
            "UA should contain macOS platform"
        );
        // All should have Safari token
        assert!(
            ua.contains("Safari/537.36"),
            "UA should contain Safari token"
        );
    }
}

#[test]
fn test_chrome_tls_fingerprints_identical_across_versions() {
    let base = CHROME_PROFILES[0].0.tls_fingerprint();

    for (profile, _) in &CHROME_PROFILES[1..] {
        let fp = profile.tls_fingerprint();
        assert_eq!(
            fp.cipher_list, base.cipher_list,
            "Cipher suites should be identical for {:?}",
            profile
        );
        assert_eq!(
            fp.sigalgs, base.sigalgs,
            "Signature algorithms should be identical for {:?}",
            profile
        );
        assert_eq!(
            fp.curves, base.curves,
            "Curves should be identical for {:?}",
            profile
        );
        assert_eq!(
            fp.extensions, base.extensions,
            "Extensions should be identical for {:?}",
            profile
        );
        assert_eq!(
            fp.grease, base.grease,
            "GREASE should be identical for {:?}",
            profile
        );
        assert_eq!(
            fp.cert_compression, base.cert_compression,
            "Cert compression should be identical for {:?}",
            profile
        );
        assert_eq!(
            fp.enable_kyber, base.enable_kyber,
            "Kyber should be identical for {:?}",
            profile
        );
    }

    // Verify shared Chrome TLS properties
    assert!(base.grease, "Chrome should use GREASE");
    assert_eq!(
        base.cert_compression,
        CertCompression::Brotli,
        "Chrome should use Brotli cert compression"
    );
    assert!(base.enable_kyber, "Chrome should enable Kyber");
}

#[test]
fn test_chrome_http2_settings_identical_across_versions() {
    let base = CHROME_PROFILES[0].0.http2_settings();

    for (profile, _) in &CHROME_PROFILES[1..] {
        let settings = profile.http2_settings();
        assert_eq!(settings.initial_window_size, base.initial_window_size);
        assert_eq!(settings.initial_window_update, base.initial_window_update);
        assert_eq!(settings.header_table_size, base.header_table_size);
        assert_eq!(settings.enable_push, base.enable_push);
        assert_eq!(settings.max_concurrent_streams, base.max_concurrent_streams);
        assert_eq!(settings.max_frame_size, base.max_frame_size);
        assert_eq!(settings.max_header_list_size, base.max_header_list_size);
        assert_eq!(settings.send_all_settings, base.send_all_settings);
        assert_eq!(settings.ping_interval, base.ping_interval);
        assert_eq!(settings.handshake_timeout, base.handshake_timeout);
        assert_eq!(
            settings
                .priority_tree
                .as_ref()
                .map(|priority_tree| &priority_tree.priorities),
            base.priority_tree
                .as_ref()
                .map(|priority_tree| &priority_tree.priorities),
        );
    }
}

#[test]
fn test_chrome_http3_fingerprints_identical_across_versions() {
    let shared = Http3Fingerprint::chrome();

    for (profile, _) in CHROME_PROFILES {
        assert_eq!(
            profile.http3_fingerprint(),
            shared,
            "HTTP/3 fingerprint should be shared for {:?}",
            profile
        );
    }
}

#[test]
fn test_chrome_sec_ch_ua_brand_strings() {
    fn get_sec_ch_ua<'a>(headers: &'a [(&str, &str)]) -> &'a str {
        headers.iter().find(|(k, _)| *k == "Sec-Ch-Ua").unwrap().1
    }

    let cases = [
        (
            142,
            chrome_142_headers(),
            r#""Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99""#,
        ),
        (
            143,
            chrome_143_headers(),
            r#""Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
        ),
        (
            144,
            chrome_144_headers(),
            r#""Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144""#,
        ),
        (
            145,
            chrome_145_headers(),
            r#""Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145""#,
        ),
        (
            146,
            chrome_146_headers(),
            r#""Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146""#,
        ),
        (
            147,
            chrome_147_headers(),
            r#""Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147""#,
        ),
        (
            148,
            chrome_148_headers(),
            r#""Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99""#,
        ),
    ];

    // All should be distinct
    let all: Vec<_> = cases
        .iter()
        .map(|(version, headers, expected)| {
            let actual = get_sec_ch_ua(headers);
            assert_eq!(actual, *expected, "Chrome {version} Sec-Ch-Ua");
            actual
        })
        .collect();
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(all[i], all[j], "Sec-Ch-Ua should differ between versions");
        }
    }
}

#[test]
fn test_chrome_sec_ch_ua_matches_chromium_grease_algorithm() {
    fn header_value<'a>(headers: &'a [(&str, &str)], name: &str) -> &'a str {
        headers
            .iter()
            .find(|(header_name, _)| *header_name == name)
            .unwrap()
            .1
    }

    fn chromium_brand_list(major_version: u16, full_version: Option<&str>) -> String {
        let greasey_chars = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
        let greasey_versions = ["8", "99", "24"];
        let brand_order = [
            [0usize, 1usize, 2usize],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ][usize::from(major_version % 6)];

        let greasey_version = greasey_versions[usize::from(major_version % 3)];
        let greasey_brand = format!(
            "Not{}A{}Brand",
            greasey_chars[usize::from(major_version % 11)],
            greasey_chars[usize::from((major_version + 1) % 11)]
        );

        let chrome_version = full_version
            .map(str::to_owned)
            .unwrap_or_else(|| major_version.to_string());
        let greasey_version = if full_version.is_some() {
            format!("{greasey_version}.0.0.0")
        } else {
            greasey_version.to_string()
        };

        let unshuffled_brands = [
            format!(r#""{greasey_brand}";v="{greasey_version}""#),
            format!(r#""Chromium";v="{chrome_version}""#),
            format!(r#""Google Chrome";v="{chrome_version}""#),
        ];
        let mut shuffled_brands = vec![String::new(); unshuffled_brands.len()];
        for (input_index, output_index) in brand_order.iter().enumerate() {
            shuffled_brands[*output_index] = unshuffled_brands[input_index].clone();
        }
        shuffled_brands.join(", ")
    }

    let cases = [
        (142, chrome_142_headers(), "142.0.7444.176"),
        (143, chrome_143_headers(), "143.0.7499.193"),
        (144, chrome_144_headers(), "144.0.7559.133"),
        (145, chrome_145_headers(), "145.0.7632.117"),
        (146, chrome_146_headers(), "146.0.7680.165"),
        (147, chrome_147_headers(), "147.0.7727.138"),
        (148, chrome_148_headers(), "148.0.7778.179"),
    ];

    for (major_version, headers, full_version) in cases {
        assert_eq!(
            header_value(&headers, "Sec-Ch-Ua"),
            chromium_brand_list(major_version, None),
            "Chrome {major_version} Sec-Ch-Ua should match Chromium GREASE"
        );
        assert_eq!(
            header_value(&headers, "Sec-Ch-Ua-Full-Version-List"),
            chromium_brand_list(major_version, Some(full_version)),
            "Chrome {major_version} full version list should match Chromium GREASE"
        );
    }
}

#[test]
fn test_chrome_sec_ch_ua_full_version_lists_match_brand_order() {
    fn get_full_version_list<'a>(headers: &'a [(&str, &str)]) -> &'a str {
        headers
            .iter()
            .find(|(k, _)| *k == "Sec-Ch-Ua-Full-Version-List")
            .unwrap()
            .1
    }

    let cases = [
        (
            142,
            chrome_142_headers(),
            r#""Chromium";v="142.0.7444.176", "Google Chrome";v="142.0.7444.176", "Not_A Brand";v="99.0.0.0""#,
        ),
        (
            143,
            chrome_143_headers(),
            r#""Google Chrome";v="143.0.7499.193", "Chromium";v="143.0.7499.193", "Not A(Brand";v="24.0.0.0""#,
        ),
        (
            144,
            chrome_144_headers(),
            r#""Not(A:Brand";v="8.0.0.0", "Chromium";v="144.0.7559.133", "Google Chrome";v="144.0.7559.133""#,
        ),
        (
            145,
            chrome_145_headers(),
            r#""Not:A-Brand";v="99.0.0.0", "Google Chrome";v="145.0.7632.117", "Chromium";v="145.0.7632.117""#,
        ),
        (
            146,
            chrome_146_headers(),
            r#""Chromium";v="146.0.7680.165", "Not-A.Brand";v="24.0.0.0", "Google Chrome";v="146.0.7680.165""#,
        ),
        (
            147,
            chrome_147_headers(),
            r#""Google Chrome";v="147.0.7727.138", "Not.A/Brand";v="8.0.0.0", "Chromium";v="147.0.7727.138""#,
        ),
        (
            148,
            chrome_148_headers(),
            r#""Chromium";v="148.0.7778.179", "Google Chrome";v="148.0.7778.179", "Not/A)Brand";v="99.0.0.0""#,
        ),
    ];

    for (version, headers, expected) in cases {
        assert_eq!(
            get_full_version_list(&headers),
            expected,
            "Chrome {version} Sec-Ch-Ua-Full-Version-List"
        );
    }
}

#[test]
fn test_chrome_all_versions_have_three_header_types() {
    // Verify each version exports navigation, AJAX, and form headers
    let versions: Vec<(Vec<_>, Vec<_>, Vec<_>)> = vec![
        (
            chrome_142_headers(),
            chrome_142_ajax_headers(),
            chrome_142_form_headers(),
        ),
        (
            chrome_143_headers(),
            chrome_143_ajax_headers(),
            chrome_143_form_headers(),
        ),
        (
            chrome_144_headers(),
            chrome_144_ajax_headers(),
            chrome_144_form_headers(),
        ),
        (
            chrome_145_headers(),
            chrome_145_ajax_headers(),
            chrome_145_form_headers(),
        ),
        (
            chrome_146_headers(),
            chrome_146_ajax_headers(),
            chrome_146_form_headers(),
        ),
        (
            chrome_147_headers(),
            chrome_147_ajax_headers(),
            chrome_147_form_headers(),
        ),
        (
            chrome_148_headers(),
            chrome_148_ajax_headers(),
            chrome_148_form_headers(),
        ),
    ];

    for (i, (nav, ajax, form)) in versions.iter().enumerate() {
        let version = 142 + i;

        // Navigation headers should have Sec-Fetch-User
        let nav_names: Vec<&str> = nav.iter().map(|(k, _)| *k).collect();
        assert!(
            nav_names.contains(&"Sec-Fetch-User"),
            "Chrome {} nav missing Sec-Fetch-User",
            version
        );
        assert!(
            nav_names.contains(&"Upgrade-Insecure-Requests"),
            "Chrome {} nav missing UIR",
            version
        );

        // AJAX headers should have Content-Type: application/json
        let ajax_ct = ajax.iter().find(|(k, _)| *k == "Content-Type");
        assert_eq!(
            ajax_ct.unwrap().1,
            "application/json",
            "Chrome {} AJAX Content-Type",
            version
        );

        // Form headers should have Content-Type: application/x-www-form-urlencoded
        let form_ct = form.iter().find(|(k, _)| *k == "Content-Type");
        assert_eq!(
            form_ct.unwrap().1,
            "application/x-www-form-urlencoded",
            "Chrome {} form Content-Type",
            version
        );

        // All should have the same User-Agent containing the version number
        let expected_ua_fragment = format!("Chrome/{}.0.0.0", version);
        for (header_type, headers) in [("nav", nav), ("ajax", ajax), ("form", form)] {
            let ua = headers.iter().find(|(k, _)| *k == "User-Agent").unwrap().1;
            assert!(
                ua.contains(&expected_ua_fragment),
                "Chrome {} {} UA should contain '{}': {}",
                version,
                header_type,
                expected_ua_fragment,
                ua
            );
        }
    }
}

#[test]
fn test_chrome_tls_constructors_match_shared() {
    // All version-specific constructors should produce the same result as chrome()
    let shared = TlsFingerprint::chrome();
    let constructors = [
        TlsFingerprint::chrome_142(),
        TlsFingerprint::chrome_143(),
        TlsFingerprint::chrome_144(),
        TlsFingerprint::chrome_145(),
        TlsFingerprint::chrome_146(),
        TlsFingerprint::chrome_147(),
        TlsFingerprint::chrome_148(),
    ];

    for (i, fp) in constructors.iter().enumerate() {
        assert_eq!(
            fp.cipher_list,
            shared.cipher_list,
            "chrome_{} ciphers",
            142 + i
        );
        assert_eq!(fp.sigalgs, shared.sigalgs, "chrome_{} sigalgs", 142 + i);
        assert_eq!(fp.curves, shared.curves, "chrome_{} curves", 142 + i);
    }
}
