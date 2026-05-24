use bytes::Bytes;
use specter::transport::h3::quic::{
    decode_retry_packet, decode_version_negotiation_packet, split_long_header_datagram,
    ConnectionId, LongHeaderType,
};

#[test]
fn native_quic_decodes_version_negotiation_packet() {
    let mut packet = vec![0x80, 0, 0, 0, 0, 4];
    packet.extend_from_slice(b"dcid");
    packet.push(4);
    packet.extend_from_slice(b"scid");
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.extend_from_slice(&0x6b3343cfu32.to_be_bytes());

    let decoded = decode_version_negotiation_packet(&packet).unwrap();

    assert_eq!(decoded.destination_cid, ConnectionId::from_static(b"dcid"));
    assert_eq!(decoded.source_cid, ConnectionId::from_static(b"scid"));
    assert_eq!(decoded.supported_versions, vec![1, 0x6b3343cf]);
}

#[test]
fn native_quic_decodes_retry_packet_token_and_integrity_tag() {
    let mut packet = vec![0xf0];
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.push(4);
    packet.extend_from_slice(b"dcid");
    packet.push(4);
    packet.extend_from_slice(b"scid");
    packet.extend_from_slice(b"retry-token");
    packet.extend_from_slice(&[0xab; 16]);

    let decoded = decode_retry_packet(&packet).unwrap();

    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.destination_cid, ConnectionId::from_static(b"dcid"));
    assert_eq!(decoded.source_cid, ConnectionId::from_static(b"scid"));
    assert_eq!(decoded.token, Bytes::from_static(b"retry-token"));
    assert_eq!(decoded.integrity_tag, [0xab; 16]);
}

#[test]
fn native_quic_splitter_accepts_terminal_retry_packet() {
    let mut packet = vec![0xf0];
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.push(4);
    packet.extend_from_slice(b"dcid");
    packet.push(4);
    packet.extend_from_slice(b"scid");
    packet.extend_from_slice(b"retry-token");
    packet.extend_from_slice(&[0xcd; 16]);

    let packets = split_long_header_datagram(&packet).unwrap();

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].packet_type, LongHeaderType::Retry);
    assert_eq!(packets[0].version, 1);
    assert_eq!(packets[0].token, Bytes::from_static(b"retry-token"));
    assert_eq!(packets[0].packet.as_ref(), packet.as_slice());
}
