use bytes::Bytes;
use specter::fingerprint::{Http3Fingerprint, TlsFingerprint};
use specter::transport::h3::quic::{
    decode_frames, decode_long_header, derive_initial_key_material,
    derive_packet_key_material_from_secret, encode_transport_parameters, open_initial_packet,
    ConnectionId, LongHeaderType, QuicFrame,
};
use specter::transport::h3::tls::{
    build_client_initial_packet, capture_client_initial_crypto, NativeQuicTlsSession,
    QuicEncryptionLevel, QuicSecretDirection, QuicTlsSecret,
};

mod helpers;

#[test]
fn native_tls_clienthello_capture_emits_initial_crypto_with_h3_alpn() {
    let captured =
        capture_client_initial_crypto("example.com", &Http3Fingerprint::chrome()).unwrap();

    assert_eq!(captured.crypto_data[0], 0x01);
    assert!(captured
        .crypto_data
        .windows(3)
        .any(|window| window == b"\x02h3"));
}

#[test]
fn native_tls_clienthello_capture_embeds_fingerprint_transport_parameters() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.max_idle_timeout_ms = 12_345;
    fingerprint.transport.initial_max_streams_bidi = 321;
    let expected = encode_transport_parameters(&fingerprint.transport);

    let captured = capture_client_initial_crypto("example.com", &fingerprint).unwrap();

    assert_eq!(captured.transport_parameters, expected);
    assert!(captured
        .crypto_data
        .windows(expected.len())
        .any(|window| window == expected.as_ref()));
}

#[test]
fn native_tls_client_initial_packet_wraps_captured_clienthello() {
    let fingerprint = Http3Fingerprint::chrome();
    let destination_cid = ConnectionId::from_static(b"destination-id");
    let source_cid = ConnectionId::from_static(b"source-id");

    let initial =
        build_client_initial_packet("example.com", &fingerprint, destination_cid, source_cid)
            .unwrap();
    let decoded_header = decode_long_header(&initial.header).unwrap();
    let keys = derive_initial_key_material(decoded_header.destination_cid.as_bytes()).unwrap();
    let opened =
        open_initial_packet(&keys.client, &initial.packet, initial.packet_number_offset).unwrap();
    let frames = decode_frames(&opened.payload).unwrap();

    assert_eq!(decoded_header.packet_type, LongHeaderType::Initial);
    assert!(initial.packet.len() >= 1200);
    assert_eq!(opened.header, initial.header);
    assert!(matches!(
        &frames[0],
        QuicFrame::Crypto { offset: 0, data } if data == &initial.crypto_data
    ));
}

#[test]
fn native_tls_clienthello_capture_has_no_tls_traffic_secrets_before_server_flight() {
    let captured =
        capture_client_initial_crypto("example.com", &Http3Fingerprint::chrome()).unwrap();

    assert!(captured.secrets.is_empty());
}

#[test]
fn native_tls_session_exposes_client_initial_without_dropping_state() {
    let mut session =
        NativeQuicTlsSession::client("example.com", &Http3Fingerprint::chrome()).unwrap();
    let initial = session.take_crypto(QuicEncryptionLevel::Initial);

    assert_eq!(initial[0], 0x01);
    assert!(initial.windows(3).any(|window| window == b"\x02h3"));
    assert_eq!(session.secrets().len(), 0);
}

#[test]
fn native_tls_session_rejects_invalid_server_initial_crypto() {
    let mut session =
        NativeQuicTlsSession::client("example.com", &Http3Fingerprint::chrome()).unwrap();

    let err = session
        .provide_crypto(QuicEncryptionLevel::Initial, b"\xff\0\0\0")
        .expect_err("invalid server crypto must fail");

    assert!(err.to_string().contains("server CRYPTO"));
}

#[test]
fn native_tls_server_accepts_client_initial_crypto_and_emits_server_flight() {
    let fingerprint = Http3Fingerprint::chrome();
    let mut client = NativeQuicTlsSession::client("localhost", &fingerprint).unwrap();
    let client_initial = client.take_crypto(QuicEncryptionLevel::Initial);
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicTlsSession::server(&fingerprint, &cert_pem, &key_pem).unwrap();

    server
        .provide_crypto(QuicEncryptionLevel::Initial, &client_initial)
        .unwrap();

    let server_initial = server.take_crypto(QuicEncryptionLevel::Initial);
    let server_handshake = server.take_crypto(QuicEncryptionLevel::Handshake);
    assert!(
        !server_initial.is_empty(),
        "server should emit ServerHello CRYPTO at Initial level"
    );
    assert!(
        !server_handshake.is_empty(),
        "server should emit EncryptedExtensions/certificate CRYPTO at Handshake level"
    );
    assert!(server_handshake
        .windows(3)
        .any(|window| window == b"\x02h3"));
}

#[test]
fn native_tls_session_applies_tls_fingerprint_curve_policy() {
    let mut tls_fingerprint = TlsFingerprint::default();
    tls_fingerprint.curves = vec!["not-a-real-group"];

    let err = match NativeQuicTlsSession::client_with_tls_fingerprint(
        "example.com",
        &Http3Fingerprint::chrome(),
        Some(&tls_fingerprint),
        true,
    ) {
        Ok(_) => panic!("invalid native TLS curve group must be rejected"),
        Err(err) => err,
    };
    let err = err.to_string();

    assert!(
        err.contains("curves") || err.contains("group") || err.contains("TLS"),
        "unexpected native TLS fingerprint error: {err}"
    );
}

#[test]
fn native_tls_recorded_secret_derives_quic_packet_keys() {
    let secret = Bytes::from_static(&[0x22; 32]);
    let recorded = QuicTlsSecret {
        direction: QuicSecretDirection::Write,
        level: QuicEncryptionLevel::Handshake,
        secret: secret.clone(),
    };

    assert_eq!(
        recorded.packet_key_material().unwrap(),
        derive_packet_key_material_from_secret(secret).unwrap()
    );
}
