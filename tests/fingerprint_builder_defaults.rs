use specter::fingerprint::http2::Http2Settings;
use specter::fingerprint::FingerprintProfile;
use specter::transport::h2::PseudoHeaderOrder;
use specter::Client;

#[test]
fn fingerprint_profile_drives_h2_defaults_without_live_network() {
    let firefox = Client::builder()
        .fingerprint(FingerprintProfile::Firefox133)
        .build()
        .unwrap();

    assert_eq!(
        firefox.fingerprint_profile(),
        FingerprintProfile::Firefox133
    );
    assert_eq!(firefox.pseudo_order(), PseudoHeaderOrder::Firefox);
    assert_eq!(firefox.http2_settings().initial_window_size, 131_072);
    assert_eq!(firefox.http2_settings().initial_window_update, 12_517_377);
    assert!(!firefox.http2_settings().send_all_settings);
    assert_eq!(
        firefox.h3_client().http3_fingerprint(),
        &FingerprintProfile::Firefox133.http3_fingerprint()
    );

    let chrome = Client::builder()
        .fingerprint(FingerprintProfile::Chrome148)
        .build()
        .unwrap();

    assert_eq!(chrome.pseudo_order(), PseudoHeaderOrder::Chrome);
    assert_eq!(chrome.http2_settings().initial_window_size, 6_291_456);
    assert!(chrome.http2_settings().send_all_settings);
    assert_eq!(
        chrome.h3_client().http3_fingerprint(),
        &FingerprintProfile::Chrome148.http3_fingerprint()
    );
}

#[test]
fn explicit_h2_overrides_take_precedence_over_profile_defaults() {
    let client = Client::builder()
        .fingerprint(FingerprintProfile::Firefox133)
        .http2_settings(Http2Settings::default())
        .pseudo_order(PseudoHeaderOrder::Standard)
        .build()
        .unwrap();

    assert_eq!(client.pseudo_order(), PseudoHeaderOrder::Standard);
    assert_eq!(client.http2_settings().initial_window_size, 6_291_456);
    assert!(client.http2_settings().send_all_settings);
}

#[test]
fn h2_window_helpers_start_from_selected_profile() {
    let client = Client::builder()
        .fingerprint(FingerprintProfile::Firefox133)
        .http2_initial_stream_window_size(Some(512_000))
        .build()
        .unwrap();

    assert_eq!(client.pseudo_order(), PseudoHeaderOrder::Firefox);
    assert_eq!(client.http2_settings().initial_window_size, 512_000);
    assert_eq!(client.http2_settings().initial_window_update, 12_517_377);
    assert!(!client.http2_settings().send_all_settings);
}
