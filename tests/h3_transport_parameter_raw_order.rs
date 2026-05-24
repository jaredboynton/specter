use bytes::Bytes;
use specter::fingerprint::{QuicTransportParams, RawQuicTransportParameter};
use specter::transport::h3::quic::{
    decode_transport_parameters, encode_server_transport_parameters, encode_transport_parameters,
    encode_transport_parameters_with_initial_source_connection_id, ConnectionId, TransportParameter,
};

#[test]
fn native_quic_transport_parameters_can_use_raw_ordered_parameters() {
    let params = QuicTransportParams {
        grease: true,
        raw_ordered_transport_parameters: Some(vec![
            RawQuicTransportParameter {
                id: 0x4a6f,
                value: b"first".to_vec(),
            },
            RawQuicTransportParameter {
                id: 0x01,
                value: vec![42],
            },
            RawQuicTransportParameter {
                id: 0x21,
                value: Vec::new(),
            },
        ]),
        ..QuicTransportParams::chrome()
    };

    let decoded = decode_transport_parameters(&encode_transport_parameters(&params)).unwrap();

    assert_eq!(
        decoded,
        vec![
            TransportParameter::Additional(0x4a6f, Bytes::from_static(b"first")),
            TransportParameter::MaxIdleTimeout(42),
            TransportParameter::Additional(0x21, Bytes::new()),
        ]
    );
}

#[test]
fn native_quic_transport_parameter_pool_key_preserves_raw_order() {
    let forward = QuicTransportParams {
        raw_ordered_transport_parameters: Some(vec![
            RawQuicTransportParameter {
                id: 0x01,
                value: vec![10],
            },
            RawQuicTransportParameter {
                id: 0x04,
                value: vec![20],
            },
        ]),
        ..QuicTransportParams::chrome()
    };
    let reversed = QuicTransportParams {
        raw_ordered_transport_parameters: Some(vec![
            RawQuicTransportParameter {
                id: 0x04,
                value: vec![20],
            },
            RawQuicTransportParameter {
                id: 0x01,
                value: vec![10],
            },
        ]),
        ..QuicTransportParams::chrome()
    };

    assert_ne!(forward.pool_key_string(), reversed.pool_key_string());
}

#[test]
fn native_quic_raw_ordered_transport_parameters_can_place_dynamic_client_cid() {
    let params = QuicTransportParams {
        raw_ordered_transport_parameters: Some(vec![
            RawQuicTransportParameter {
                id: 0x01,
                value: vec![42],
            },
            RawQuicTransportParameter::initial_source_connection_id(),
            RawQuicTransportParameter {
                id: 0x04,
                value: vec![63],
            },
        ]),
        ..QuicTransportParams::chrome()
    };

    let decoded = decode_transport_parameters(
        &encode_transport_parameters_with_initial_source_connection_id(
            &params,
            &ConnectionId::from_static(b"client-scid"),
        ),
    )
    .unwrap();

    assert_eq!(
        decoded,
        vec![
            TransportParameter::MaxIdleTimeout(42),
            TransportParameter::InitialSourceConnectionId(Bytes::from_static(b"client-scid")),
            TransportParameter::InitialMaxData(63),
        ]
    );
}

#[test]
fn native_quic_raw_ordered_transport_parameters_can_place_dynamic_server_cids() {
    let params = QuicTransportParams {
        raw_ordered_transport_parameters: Some(vec![
            RawQuicTransportParameter::initial_source_connection_id(),
            RawQuicTransportParameter {
                id: 0x01,
                value: vec![25],
            },
            RawQuicTransportParameter::original_destination_connection_id(),
            RawQuicTransportParameter::retry_source_connection_id(),
        ]),
        ..QuicTransportParams::chrome()
    };

    let decoded = decode_transport_parameters(&encode_server_transport_parameters(
        &params,
        &ConnectionId::from_static(b"client-dcid"),
        &ConnectionId::from_static(b"server-scid"),
        Some(&ConnectionId::from_static(b"retry-scid")),
    ))
    .unwrap();

    assert_eq!(
        decoded,
        vec![
            TransportParameter::InitialSourceConnectionId(Bytes::from_static(b"server-scid")),
            TransportParameter::MaxIdleTimeout(25),
            TransportParameter::OriginalDestinationConnectionId(Bytes::from_static(
                b"client-dcid",
            )),
            TransportParameter::RetrySourceConnectionId(Bytes::from_static(b"retry-scid")),
        ]
    );
}
