use specter::fingerprint::{FingerprintProfile, H3Settings, Http3Fingerprint, QuicTransportParams};
use specter::{Client, H3Backend, H3Client};

#[test]
fn chrome_http3_fingerprint_exposes_quic_h3_and_grease_knobs() {
    let fingerprint = Http3Fingerprint::chrome();

    assert_eq!(fingerprint.transport.initial_max_data, 15_663_105);
    assert_eq!(fingerprint.transport.max_send_udp_payload_size, 1350);
    assert_eq!(fingerprint.transport.initial_max_streams_bidi, 100);
    assert_eq!(fingerprint.transport.ack_delay_exponent, 3);
    assert_eq!(fingerprint.transport.max_ack_delay_ms, 25);
    assert_eq!(fingerprint.transport.active_connection_id_limit, 2);
    assert!(fingerprint.transport.disable_active_migration);
    assert!(fingerprint.transport.grease);

    assert_eq!(fingerprint.settings.qpack_max_table_capacity, Some(0));
    assert_eq!(fingerprint.settings.qpack_blocked_streams, Some(0));
    assert!(fingerprint.settings.enable_extended_connect);
    assert_eq!(fingerprint.alpn_protocols, vec![b"h3".to_vec()]);

    assert_eq!(
        FingerprintProfile::Chrome148.http3_fingerprint(),
        fingerprint
    );
}

#[test]
fn custom_http3_fingerprint_flows_through_h3_client_and_unified_builder() {
    let fingerprint = Http3Fingerprint {
        transport: QuicTransportParams {
            initial_max_data: 42_000,
            max_send_udp_payload_size: 1232,
            initial_congestion_window_packets: 12,
            max_pacing_rate: Some(9_000_000),
            ..QuicTransportParams::chrome()
        },
        settings: H3Settings {
            qpack_max_table_capacity: Some(4096),
            qpack_blocked_streams: Some(16),
            max_field_section_size: Some(131_072),
            additional_settings: vec![(0x21, 1)],
            ..H3Settings::chrome()
        },
        ..Http3Fingerprint::chrome()
    };

    let h3_client = H3Client::new().with_http3_fingerprint(fingerprint.clone());
    assert_eq!(h3_client.http3_fingerprint(), &fingerprint);

    let client = Client::builder()
        .h3_fingerprint(fingerprint.clone())
        .build()
        .unwrap();
    assert_eq!(client.h3_client().http3_fingerprint(), &fingerprint);
}

#[test]
fn h3_backend_selection_flows_through_h3_client_and_unified_builder() {
    let h3_client = H3Client::new().with_h3_backend(H3Backend::Native);
    assert_eq!(h3_client.h3_backend(), H3Backend::Native);

    let client = Client::builder()
        .h3_backend(H3Backend::Native)
        .build()
        .unwrap();
    assert_eq!(client.h3_client().h3_backend(), H3Backend::Native);
}

#[test]
fn h3_backend_defaults_to_native_client_path() {
    assert_eq!(H3Client::new().h3_backend(), H3Backend::Native);
    assert_eq!(
        H3Client::with_fingerprint(FingerprintProfile::Chrome148.tls_fingerprint()).h3_backend(),
        H3Backend::Native
    );

    let client = Client::builder().build().unwrap();
    assert_eq!(client.h3_client().h3_backend(), H3Backend::Native);
}
