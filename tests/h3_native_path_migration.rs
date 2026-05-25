use specter::fingerprint::Http3Fingerprint;
use specter::transport::h3::handshake::{NativeQuicHandshake, NativeQuicServerHandshake, ServerH3Event};
use specter::transport::h3::path::QuicPathSet;
use specter::transport::h3::quic::ConnectionId;
use std::net::SocketAddr;
use std::time::Instant;

mod helpers;

use bytes::Bytes;

fn migration_enabled_fingerprint() -> Http3Fingerprint {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.transport.disable_active_migration = false;
    fingerprint
}

fn completed_migration_handshake() -> (
    Http3Fingerprint,
    NativeQuicHandshake,
    NativeQuicServerHandshake,
) {
    let fingerprint = migration_enabled_fingerprint();
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let mut client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .unwrap();
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid,
        client_source_cid,
        ConnectionId::from_static(b"native-server-cid"),
    )
    .unwrap();
    let server_flight = server
        .process_client_initial(client.client_initial().packet.as_ref())
        .unwrap();
    let processed = client
        .process_server_datagram(&server_flight.datagram)
        .unwrap();
    let client_finished = Bytes::from(
        processed
            .iter()
            .flat_map(|processed| processed.handshake_crypto_out.iter().copied())
            .collect::<Vec<_>>(),
    );
    let client_finished_packet = client
        .build_client_handshake_crypto_packet(client_finished)
        .unwrap()
        .unwrap();
    server
        .process_client_handshake(client_finished_packet.packet.as_ref())
        .unwrap();
    (fingerprint, client, server)
}

#[test]
fn native_client_path_set_marks_validated_after_handshake_validation() {
    let (_, mut client, mut server) = completed_migration_handshake();
    let original_peer = SocketAddr::from(([127, 0, 0, 1], 4433));
    let migrated_peer = SocketAddr::from(([127, 0, 0, 1], 4434));
    let mut path_set = QuicPathSet::new();
    path_set.install_primary(original_peer);
    path_set.observe_packet_from(migrated_peer, 1200, Instant::now());

    let challenge = *b"MIGRSET!";
    let challenge_packet = server
        .build_server_path_challenge_packet_for_address(migrated_peer, challenge)
        .expect("server path challenge");
    client
        .open_server_h3_event_packet(challenge_packet.packet.as_ref())
        .expect("client opens server path challenge");
    let response = client
        .build_client_path_response_packet(challenge)
        .expect("client path response");
    server
        .open_client_h3_event_packet_from(response.packet.as_ref(), migrated_peer)
        .expect("server validates migrated peer");

    assert!(client.is_client_path_address_validated(&migrated_peer));
    assert!(path_set.mark_validated(migrated_peer));
    assert!(path_set.promote_to_primary(migrated_peer));
    assert!(path_set.may_send_to(migrated_peer, 1_000_000));
}

#[test]
fn native_server_connection_migration_close_uses_transport_error_code() {
    let (_, mut client, mut server) = completed_migration_handshake();
    let close = server
        .build_server_connection_migration_close_packet()
        .expect("connection migration close");
    assert!(server.close_state().is_closing());
    let events = client
        .open_server_h3_event_packet(close.packet.as_ref())
        .expect("client opens migration close");
    assert!(
        events.iter().any(|event| matches!(
            event,
            ServerH3Event::ConnectionClose {
                error_code: 0x0a,
                ..
            }
        )),
        "disabled-migration close must use CONNECTION_MIGRATION (0x0a)"
    );
}

#[test]
#[ignore = "run with SPECTER_MIGRATION_SOAK=1 for long peer-address migration soak"]
fn native_path_migration_soak_across_active_peer_address_changes() {
    if std::env::var("SPECTER_MIGRATION_SOAK").ok().as_deref() != Some("1") {
        return;
    }
    let mut path_set = QuicPathSet::new();
    let base = SocketAddr::from(([127, 0, 0, 1], 50_000));
    path_set.install_primary(base);
    for cycle in 0..20_u16 {
        let migrated = SocketAddr::from(([127, 0, 0, 1], 50_001 + cycle as u16));
        path_set.observe_packet_from(migrated, 1200, Instant::now());
        let mut token = [0u8; 8];
        token[..2].copy_from_slice(&cycle.to_be_bytes());
        assert!(path_set.issue_challenge(migrated, token));
        assert!(path_set.observe_path_response(migrated, token));
        assert!(path_set.promote_to_primary(migrated));
        assert!(path_set.may_send_to(migrated, 256 * 1024));
    }
}
