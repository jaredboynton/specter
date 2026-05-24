//! RFC9002 packet-space recovery, PTO, and congestion control coverage for
//! the native QUIC handshake. These tests target the public surface that the
//! native H3 driver consumes: `RecoveryState`, the per-space loss-detection
//! timer, the PTO backoff, congestion controller bytes_in_flight, and the
//! Initial CRYPTO PTO retransmission introduced for P0.1.

mod helpers {
    pub mod tls {
        include!("helpers/tls.rs");
    }
}

use std::time::{Duration, Instant};

use bytes::Bytes;
use specter::fingerprint::Http3Fingerprint;
use specter::transport::h3::handshake::{NativeQuicHandshake, NativeQuicServerHandshake};
use specter::transport::h3::quic::{decode_frames, ConnectionId, LongHeaderType, QuicFrame};
use specter::transport::h3::recovery::{
    LossDetectionOutcome, PacketNumberSpace, RecoveryState, SentPacketInfo,
};
use specter::transport::h3::tls::{QuicEncryptionLevel, QuicSecretDirection, QuicTlsSecret};

fn build_client_handshake() -> NativeQuicHandshake {
    NativeQuicHandshake::client_with_verify_peer(
        "example.com",
        &Http3Fingerprint::chrome(),
        ConnectionId::from_static(b"server-dcid"),
        ConnectionId::from_static(b"client-scid"),
        false,
    )
    .expect("native client handshake")
}

fn install_handshake_secrets(handshake: &mut NativeQuicHandshake) {
    let secret = Bytes::from_static(&[0x76; 32]);
    handshake
        .install_tls_secrets(&[QuicTlsSecret {
            direction: QuicSecretDirection::Write,
            level: QuicEncryptionLevel::Handshake,
            secret,
        }])
        .expect("install client write handshake secret");
}

fn install_application_secrets(handshake: &mut NativeQuicHandshake) {
    install_handshake_secrets(handshake);
    handshake
        .install_tls_secrets(&[
            QuicTlsSecret {
                direction: QuicSecretDirection::Write,
                level: QuicEncryptionLevel::Application,
                secret: Bytes::from_static(&[0x77; 32]),
            },
            QuicTlsSecret {
                direction: QuicSecretDirection::Read,
                level: QuicEncryptionLevel::Application,
                secret: Bytes::from_static(&[0x78; 32]),
            },
        ])
        .expect("install client application secrets");
}

#[test]
fn rfc9002_recovery_state_tracks_bytes_in_flight_round_trip() {
    let mut recovery = RecoveryState::default();
    let now = Instant::now();
    recovery.on_packet_sent(
        PacketNumberSpace::Initial,
        0,
        SentPacketInfo::new(now, 1200, true, true),
    );
    recovery.on_packet_sent(
        PacketNumberSpace::Initial,
        1,
        SentPacketInfo::new(now, 1000, true, true),
    );
    assert_eq!(recovery.congestion().bytes_in_flight(), 2200);

    let ack_frame = QuicFrame::Ack {
        largest_acknowledged: 1,
        ack_delay: 0,
        first_ack_range: 1,
        ranges: Vec::new(),
    };
    let outcome = recovery
        .on_ack_received(PacketNumberSpace::Initial, &ack_frame, 3, now)
        .expect("ack");
    assert_eq!(outcome.newly_acked.len(), 2);
    assert_eq!(recovery.congestion().bytes_in_flight(), 0);
}

#[test]
fn rfc9002_recovery_pto_doubles_on_each_timeout_until_ack_resets_it() {
    let mut recovery = RecoveryState::default();
    let now = Instant::now();
    recovery.mark_handshake_complete();
    recovery.on_packet_sent(
        PacketNumberSpace::Application,
        1,
        SentPacketInfo::new(now, 1200, true, true),
    );

    let initial_pto = recovery.current_pto();
    let outcome = recovery.on_loss_detection_timeout(now);
    assert!(matches!(
        outcome,
        LossDetectionOutcome::Pto {
            space: PacketNumberSpace::Application,
        }
    ));
    assert_eq!(recovery.pto_count(), 1);
    assert_eq!(recovery.current_pto(), initial_pto * 2);

    let _ = recovery.on_loss_detection_timeout(now);
    assert_eq!(recovery.pto_count(), 2);
    assert_eq!(recovery.current_pto(), initial_pto * 4);

    recovery.on_packet_sent(
        PacketNumberSpace::Application,
        2,
        SentPacketInfo::new(now, 1200, true, true),
    );
    let ack = QuicFrame::Ack {
        largest_acknowledged: 2,
        ack_delay: 0,
        first_ack_range: 0,
        ranges: Vec::new(),
    };
    let _ = recovery
        .on_ack_received(
            PacketNumberSpace::Application,
            &ack,
            3,
            now + Duration::from_millis(50),
        )
        .expect("ack");
    assert_eq!(recovery.pto_count(), 0);
    assert_eq!(recovery.current_pto(), initial_pto);
}

#[test]
fn rfc9002_recovery_packet_threshold_declares_old_unacked_lost() {
    let mut recovery = RecoveryState::default();
    let now = Instant::now();
    for pn in 0..=4u64 {
        recovery.on_packet_sent(
            PacketNumberSpace::Application,
            pn,
            SentPacketInfo::new(now, 1200, true, true),
        );
    }
    let ack = QuicFrame::Ack {
        largest_acknowledged: 4,
        ack_delay: 0,
        first_ack_range: 0,
        ranges: Vec::new(),
    };
    let outcome = recovery
        .on_ack_received(PacketNumberSpace::Application, &ack, 3, now)
        .expect("ack");
    let lost: Vec<u64> = outcome.lost.iter().map(|(pn, _)| *pn).collect();
    assert_eq!(lost, vec![0, 1]);
}

#[test]
fn rfc9002_recovery_time_threshold_marks_packet_lost_after_loss_delay() {
    let mut recovery = RecoveryState::default();
    let base = Instant::now();
    recovery.on_packet_sent(
        PacketNumberSpace::Application,
        1,
        SentPacketInfo::new(base, 1200, true, true),
    );
    let later = base + Duration::from_millis(1200);
    recovery.on_packet_sent(
        PacketNumberSpace::Application,
        2,
        SentPacketInfo::new(later, 1200, true, true),
    );
    let ack = QuicFrame::Ack {
        largest_acknowledged: 2,
        ack_delay: 0,
        first_ack_range: 0,
        ranges: Vec::new(),
    };
    let outcome = recovery
        .on_ack_received(
            PacketNumberSpace::Application,
            &ack,
            3,
            later + Duration::from_millis(50),
        )
        .expect("ack");
    let lost: Vec<u64> = outcome.lost.iter().map(|(pn, _)| *pn).collect();
    assert_eq!(lost, vec![1]);
}

#[test]
fn rfc9002_recovery_pto_target_picks_initial_then_handshake_when_no_in_flight() {
    let mut recovery = RecoveryState::default();
    recovery.set_has_handshake_keys(false);
    let initial_space = recovery.pto_time_and_space().expect("anti-deadlock pto").0;
    assert_eq!(initial_space, PacketNumberSpace::Initial);

    recovery.set_has_handshake_keys(true);
    let handshake_space = recovery
        .pto_time_and_space()
        .expect("anti-deadlock pto with handshake keys")
        .0;
    assert_eq!(handshake_space, PacketNumberSpace::Handshake);
}

#[test]
fn rfc9002_recovery_pto_picks_earliest_space_when_multiple_spaces_in_flight() {
    let mut recovery = RecoveryState::default();
    let now = Instant::now();
    recovery.set_has_handshake_keys(true);
    recovery.on_packet_sent(
        PacketNumberSpace::Initial,
        0,
        SentPacketInfo::new(now, 1200, true, true),
    );
    recovery.on_packet_sent(
        PacketNumberSpace::Handshake,
        0,
        SentPacketInfo::new(now + Duration::from_millis(10), 1200, true, true),
    );
    let (space, _) = recovery.pto_time_and_space().expect("pto");
    assert_eq!(space, PacketNumberSpace::Initial);
}

#[test]
fn rfc9002_recovery_persistent_congestion_collapses_cwnd_after_long_loss_burst() {
    let mut recovery = RecoveryState::default();
    let now = Instant::now();
    recovery.mark_handshake_complete();
    recovery.on_packet_sent(
        PacketNumberSpace::Application,
        0,
        SentPacketInfo::new(now - Duration::from_millis(20), 1200, true, true),
    );
    let seed_ack = QuicFrame::Ack {
        largest_acknowledged: 0,
        ack_delay: 0,
        first_ack_range: 0,
        ranges: Vec::new(),
    };
    let _ = recovery
        .on_ack_received(PacketNumberSpace::Application, &seed_ack, 3, now)
        .expect("seed rtt sample");

    let pc_unit =
        recovery.rtt().smoothed_rtt() + recovery.rtt().rttvar() * 4 + recovery.max_ack_delay();
    let span = pc_unit * 3 + Duration::from_millis(50);
    let earliest = now;
    let latest = earliest + span;
    recovery.on_packet_sent(
        PacketNumberSpace::Application,
        1,
        SentPacketInfo::new(earliest, 1200, true, true),
    );
    recovery.on_packet_sent(
        PacketNumberSpace::Application,
        2,
        SentPacketInfo::new(latest, 1200, true, true),
    );
    recovery.on_packet_sent(
        PacketNumberSpace::Application,
        5,
        SentPacketInfo::new(latest + Duration::from_millis(1), 1200, true, true),
    );
    let ack = QuicFrame::Ack {
        largest_acknowledged: 5,
        ack_delay: 0,
        first_ack_range: 0,
        ranges: Vec::new(),
    };
    let outcome = recovery
        .on_ack_received(
            PacketNumberSpace::Application,
            &ack,
            3,
            latest + Duration::from_millis(2),
        )
        .expect("ack");
    let lost: Vec<u64> = outcome.lost.iter().map(|(pn, _)| *pn).collect();
    assert!(lost.contains(&1) && lost.contains(&2));

    let min_cwnd = recovery.congestion().max_datagram_size() * 2;
    assert_eq!(recovery.congestion().cwnd(), min_cwnd);
}

#[test]
fn rfc9002_recovery_ack_received_updates_smoothed_rtt_and_clears_pto() {
    let mut recovery = RecoveryState::default();
    let now = Instant::now();
    let sent = now - Duration::from_millis(80);
    recovery.on_packet_sent(
        PacketNumberSpace::Application,
        1,
        SentPacketInfo::new(sent, 1200, true, true),
    );
    let ack = QuicFrame::Ack {
        largest_acknowledged: 1,
        ack_delay: 0,
        first_ack_range: 0,
        ranges: Vec::new(),
    };
    let outcome = recovery
        .on_ack_received(PacketNumberSpace::Application, &ack, 3, now)
        .expect("ack");
    assert_eq!(outcome.newly_acked.len(), 1);
    assert_eq!(recovery.rtt().latest_rtt(), Some(Duration::from_millis(80)));
    assert!(recovery.rtt().smoothed_rtt() > Duration::ZERO);
    assert_eq!(recovery.pto_count(), 0);
}

#[test]
fn rfc9002_recovery_discard_space_returns_bytes_in_flight_and_resets_pto_count() {
    let mut recovery = RecoveryState::default();
    let now = Instant::now();
    recovery.on_packet_sent(
        PacketNumberSpace::Handshake,
        0,
        SentPacketInfo::new(now, 1100, true, true),
    );
    recovery.on_packet_sent(
        PacketNumberSpace::Handshake,
        1,
        SentPacketInfo::new(now, 900, true, true),
    );
    assert_eq!(recovery.congestion().bytes_in_flight(), 2000);
    let _ = recovery.on_loss_detection_timeout(now);
    assert!(recovery.pto_count() >= 1);

    recovery.discard_space(PacketNumberSpace::Handshake);

    assert_eq!(recovery.pto_count(), 0);
    assert_eq!(recovery.congestion().bytes_in_flight(), 0);
    assert!(recovery
        .space(PacketNumberSpace::Handshake)
        .sent_packets()
        .is_empty());
}

#[test]
fn native_h3_client_initial_send_records_initial_in_recovery_state() {
    let mut handshake = build_client_handshake();
    let initial_packet_size = handshake.client_initial().packet.len();
    let before = handshake.recovery().congestion().bytes_in_flight();

    handshake.record_client_initial_sent_at(Instant::now());

    let after = handshake.recovery().congestion().bytes_in_flight();
    assert_eq!(
        after,
        before + initial_packet_size as u64,
        "client Initial datagram must be accounted into bytes_in_flight",
    );
    assert!(handshake.loss_detection_timer().is_some());
    assert!(handshake
        .recovery()
        .space(PacketNumberSpace::Initial)
        .has_ack_eliciting_in_flight());
}

#[test]
fn native_h3_client_initial_pto_retransmits_initial_crypto_with_fresh_packet_number() {
    let mut handshake = build_client_handshake();
    let original_packet_number = handshake.client_initial().packet.clone();
    handshake.record_client_initial_sent_at(Instant::now());

    let retransmits = handshake
        .retransmit_pto_client_initial_crypto_packets(Instant::now(), Duration::ZERO)
        .expect("client Initial PTO retransmit");

    assert_eq!(
        retransmits.len(),
        1,
        "expected exactly one Initial CRYPTO PTO probe",
    );
    assert_eq!(
        retransmits[0].crypto_data,
        handshake.client_initial().crypto_data,
        "PTO probe must replay the original Initial CRYPTO bytes",
    );
    assert!(
        retransmits[0].packet.len() >= 1200,
        "PTO probe must still be padded to at least 1200 bytes per RFC9000 § 14.1",
    );
    assert_ne!(
        retransmits[0].packet, original_packet_number,
        "PTO probe must use a fresh packet number, producing different ciphertext",
    );
}

#[test]
fn native_h3_client_handshake_crypto_send_records_packet_in_recovery_state() {
    let mut handshake = build_client_handshake();
    install_handshake_secrets(&mut handshake);

    let _packet = handshake
        .build_client_handshake_crypto_packet(Bytes::from_static(b"client-finished"))
        .expect("handshake crypto packet")
        .expect("non-empty crypto bytes produce a packet");

    let recovery = handshake.recovery();
    assert!(recovery
        .space(PacketNumberSpace::Handshake)
        .has_ack_eliciting_in_flight());
    assert!(
        recovery.congestion().bytes_in_flight() > 0,
        "Handshake CRYPTO packet must be counted in bytes_in_flight",
    );
    assert!(handshake.loss_detection_timer().is_some());
}

#[test]
fn native_h3_client_application_send_arms_loss_detection_timer_after_app_keys() {
    let mut handshake = build_client_handshake();
    install_application_secrets(&mut handshake);

    let preface_packets = handshake
        .build_client_h3_preface_packets(&Http3Fingerprint::chrome())
        .expect("h3 preface stream packets");
    assert!(!preface_packets.is_empty());
    assert!(handshake.loss_detection_timer().is_some());
    let bytes_in_flight = handshake.recovery().congestion().bytes_in_flight();
    assert!(
        bytes_in_flight > 0,
        "application packets must increase bytes_in_flight",
    );
}

#[test]
fn native_h3_server_retransmits_initial_and_handshake_crypto_after_pto() {
    let fingerprint = Http3Fingerprint::chrome();
    let client_destination_cid = ConnectionId::from_static(b"server-dcid");
    let client_source_cid = ConnectionId::from_static(b"client-scid");
    let server_source_cid = ConnectionId::from_static(b"native-server-cid");
    let client = NativeQuicHandshake::client_with_verify_peer(
        "localhost",
        &fingerprint,
        client_destination_cid.clone(),
        client_source_cid.clone(),
        false,
    )
    .expect("client handshake");
    let (cert_pem, key_pem) = helpers::tls::cached_cert_and_key_pem();
    let mut server = NativeQuicServerHandshake::new(
        &fingerprint,
        &cert_pem,
        &key_pem,
        client_destination_cid.clone(),
        client_source_cid,
        server_source_cid,
    )
    .expect("server handshake");
    let server_flight = server
        .process_client_initial(client.client_initial().packet.as_ref())
        .expect("server initial flight");

    let retransmits = server
        .retransmit_pto_server_crypto_packets(Instant::now(), Duration::ZERO)
        .expect("server crypto pto retransmits");
    assert_eq!(retransmits.len(), 2);
    assert_eq!(retransmits[0].packet_type, LongHeaderType::Initial);
    assert_eq!(
        retransmits[0].crypto_data,
        server_flight.packets[0].crypto_data,
    );
    assert_eq!(retransmits[1].packet_type, LongHeaderType::Handshake);
    assert_eq!(
        retransmits[1].crypto_data,
        server_flight.packets[1].crypto_data,
    );
    let _ = decode_frames; // re-export check for downstream callers
}
