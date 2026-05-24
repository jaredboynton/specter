use bytes::Bytes;
use specter::fingerprint::{
    H3Settings, Http3Fingerprint, QpackHeaderBlockStrategy, QpackStringEncodingStrategy,
};
use specter::transport::h3::native::{
    build_request_headers, build_websocket_connect_headers, decode_frame, decode_frames,
    decode_header_block, decode_unidirectional_stream, encode_client_preface_streams,
    encode_fingerprint_settings_payload, encode_frame, encode_header_block, encode_request_stream,
    encode_request_stream_with_fingerprint, encode_settings_payload, encode_unidirectional_stream,
    H3Frame, H3Header, H3Setting, H3StreamType, H3UnidirectionalStream,
};

#[test]
fn native_h3_codec_round_trips_data_headers_and_goaway_frames() {
    let data = H3Frame::Data(Bytes::from_static(b"hello"));
    assert_eq!(decode_frame(&encode_frame(&data)).unwrap(), data);

    let headers = H3Frame::Headers(Bytes::from_static(b"\x00\xd1\xd7"));
    assert_eq!(decode_frame(&encode_frame(&headers)).unwrap(), headers);

    let goaway = H3Frame::GoAway { id: 4 };
    assert_eq!(decode_frame(&encode_frame(&goaway)).unwrap(), goaway);
}

#[test]
fn native_h3_settings_payload_preserves_fingerprint_order() {
    let settings = H3Settings {
        qpack_max_table_capacity: Some(4096),
        qpack_blocked_streams: Some(16),
        max_field_section_size: Some(131_072),
        enable_extended_connect: true,
        additional_settings: vec![(0x21, 1), (0x2b, 0)],
        raw_ordered_settings: None,
    };

    assert_eq!(
        encode_settings_payload(&settings),
        vec![
            H3Setting::QpackMaxTableCapacity(4096),
            H3Setting::QpackBlockedStreams(16),
            H3Setting::MaxFieldSectionSize(131_072),
            H3Setting::EnableConnectProtocol(1),
            H3Setting::Additional(0x21, 1),
            H3Setting::Additional(0x2b, 0),
        ]
    );
}

#[test]
fn native_h3_settings_payload_can_use_raw_ordered_settings() {
    let settings = H3Settings {
        raw_ordered_settings: Some(vec![(0x8, 1), (0x21, 0), (0x1, 4096), (0x6, 65_536)]),
        ..H3Settings::chrome()
    };

    assert_eq!(
        encode_settings_payload(&settings),
        vec![
            H3Setting::EnableConnectProtocol(1),
            H3Setting::Additional(0x21, 0),
            H3Setting::QpackMaxTableCapacity(4096),
            H3Setting::MaxFieldSectionSize(65_536),
        ]
    );
}

#[test]
fn native_h3_settings_frame_decodes_known_and_unknown_settings() {
    let frame = H3Frame::Settings(vec![
        H3Setting::QpackMaxTableCapacity(0),
        H3Setting::QpackBlockedStreams(0),
        H3Setting::EnableConnectProtocol(1),
        H3Setting::Additional(0x2b, 7),
    ]);

    assert_eq!(decode_frame(&encode_frame(&frame)).unwrap(), frame);
}

#[test]
fn native_h3_request_header_builder_filters_hop_by_hop_headers() {
    let uri: http::Uri = "https://example.test/search?q=rust".parse().unwrap();
    let headers = build_request_headers(
        &http::Method::GET,
        &uri,
        &[
            ("User-Agent".into(), "specter".into()),
            ("Connection".into(), "keep-alive".into()),
            ("X-Trace".into(), "one".into()),
        ],
    )
    .unwrap();

    let pairs = headers
        .iter()
        .map(|header| (header.name().to_string(), header.value().to_string()))
        .collect::<Vec<_>>();

    assert_eq!(
        &pairs[..4],
        &[
            (":method".into(), "GET".into()),
            (":scheme".into(), "https".into()),
            (":authority".into(), "example.test".into()),
            (":path".into(), "/search?q=rust".into()),
        ]
    );
    assert!(pairs.contains(&("user-agent".into(), "specter".into())));
    assert!(pairs.contains(&("x-trace".into(), "one".into())));
    assert!(!pairs.iter().any(|(name, _)| name == "connection"));
}

#[test]
fn native_h3_rfc9220_header_builder_rejects_h1_websocket_bootstrap() {
    let uri: http::Uri = "https://example.test/chat".parse().unwrap();

    for name in [
        "Connection",
        "Upgrade",
        "Host",
        "Sec-WebSocket-Key",
        "Sec-WebSocket-Accept",
        "Sec-WebSocket-Extensions",
    ] {
        let err = build_websocket_connect_headers(&uri, &[(name.into(), "x".into())])
            .expect_err("forbidden H1 websocket header must fail");
        assert!(err.to_string().contains("not allowed"));
    }
}

#[test]
fn native_h3_client_preface_preserves_browser_stream_order() {
    let streams = encode_client_preface_streams(&Http3Fingerprint::chrome());

    assert_eq!(
        streams
            .iter()
            .map(|stream| stream.stream_type)
            .collect::<Vec<_>>(),
        vec![
            H3StreamType::Control,
            H3StreamType::QpackEncoder,
            H3StreamType::QpackDecoder,
            H3StreamType::Grease(0x21),
        ]
    );

    let control = &streams[0].payload;
    assert_eq!(
        decode_frame(control).unwrap(),
        H3Frame::Settings(encode_fingerprint_settings_payload(
            &Http3Fingerprint::chrome()
        ))
    );
}

#[test]
fn native_h3_client_preface_uses_fingerprint_qpack_stream_payloads() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.stream.qpack_encoder_stream_payload = b"\x02\x80dynamic".to_vec();
    fingerprint.stream.qpack_decoder_stream_payload = b"\x00ack".to_vec();

    let streams = encode_client_preface_streams(&fingerprint);
    let encoder = streams
        .iter()
        .find(|stream| stream.stream_type == H3StreamType::QpackEncoder)
        .expect("QPACK encoder stream should exist");
    let decoder = streams
        .iter()
        .find(|stream| stream.stream_type == H3StreamType::QpackDecoder)
        .expect("QPACK decoder stream should exist");

    assert_eq!(encoder.payload, Bytes::from_static(b"\x02\x80dynamic"));
    assert_eq!(decoder.payload, Bytes::from_static(b"\x00ack"));
}

#[test]
fn native_h3_client_preface_emits_grease_setting_and_frame_when_enabled() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.stream.send_grease_frames = true;
    let streams = encode_client_preface_streams(&fingerprint);

    let control_frames = decode_frames(&streams[0].payload).unwrap();

    assert_eq!(
        control_frames,
        vec![
            H3Frame::Settings(vec![
                H3Setting::QpackMaxTableCapacity(0),
                H3Setting::QpackBlockedStreams(0),
                H3Setting::EnableConnectProtocol(1),
                H3Setting::Additional(0x21, 0),
            ]),
            H3Frame::Unknown {
                frame_type: 0x21,
                payload: Bytes::new(),
            },
        ]
    );
}

#[test]
fn native_h3_client_preface_omits_grease_frame_when_disabled() {
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.stream.send_grease_frames = false;
    let streams = encode_client_preface_streams(&fingerprint);

    let control_frames = decode_frames(&streams[0].payload).unwrap();

    assert_eq!(
        control_frames,
        vec![H3Frame::Settings(vec![
            H3Setting::QpackMaxTableCapacity(0),
            H3Setting::QpackBlockedStreams(0),
            H3Setting::EnableConnectProtocol(1),
        ])]
    );
}

#[test]
fn native_h3_unidirectional_stream_prefixes_stream_type_varint() {
    let encoded = encode_unidirectional_stream(&H3UnidirectionalStream {
        stream_type: H3StreamType::Control,
        payload: Bytes::from_static(b"\x04\x00"),
    });

    assert_eq!(encoded, Bytes::from_static(b"\x00\x04\x00"));
    assert_eq!(
        decode_unidirectional_stream(&encoded).unwrap(),
        H3UnidirectionalStream {
            stream_type: H3StreamType::Control,
            payload: Bytes::from_static(b"\x04\x00"),
        }
    );

    let grease = encode_unidirectional_stream(&H3UnidirectionalStream {
        stream_type: H3StreamType::Grease(0x21),
        payload: Bytes::from_static(b"grease"),
    });
    assert_eq!(grease[0], 0x21);
    assert_eq!(
        decode_unidirectional_stream(&grease).unwrap(),
        H3UnidirectionalStream {
            stream_type: H3StreamType::Grease(0x21),
            payload: Bytes::from_static(b"grease"),
        }
    );
}

#[test]
fn native_qpack_decodes_status_200_static_index() {
    let headers = decode_header_block(&[0x00, 0x00, 0xd9]).unwrap();

    assert_eq!(headers, vec![H3Header::new(":status", "200")]);
}

#[test]
fn native_qpack_decodes_content_type_text_plain_static_index() {
    let headers = decode_header_block(&[0x00, 0x00, 0xf5]).unwrap();

    assert_eq!(headers, vec![H3Header::new("content-type", "text/plain")]);
}

#[test]
fn native_qpack_encodes_static_and_literal_request_headers() {
    let headers = vec![
        H3Header::new(":method", "GET"),
        H3Header::new(":scheme", "https"),
        H3Header::new(":path", "/"),
        H3Header::new(":authority", "example.test"),
        H3Header::new("x-trace", "one"),
    ];

    let block = encode_header_block(&headers);

    assert_eq!(&block[..5], &[0x00, 0x00, 0xd1, 0xd7, 0xc1]);
    assert_eq!(decode_header_block(&block).unwrap(), headers);
}

#[test]
fn native_qpack_request_strategy_can_force_literal_header_fields() {
    let headers = vec![
        H3Header::new(":method", "GET"),
        H3Header::new(":scheme", "https"),
        H3Header::new(":path", "/"),
        H3Header::new(":authority", "example.test"),
    ];
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.stream.request_header_block_strategy = QpackHeaderBlockStrategy::LiteralOnly;

    let stream = encode_request_stream_with_fingerprint(&headers, None, &fingerprint);
    let frames = decode_frames(&stream).unwrap();
    let H3Frame::Headers(block) = &frames[0] else {
        panic!("first request-stream frame must be HEADERS");
    };

    assert_ne!(&block[..5], &[0x00, 0x00, 0xd1, 0xd7, 0xc1]);
    assert_eq!(decode_header_block(block.as_ref()).unwrap(), headers);
}

#[test]
fn native_qpack_request_strategy_can_force_huffman_strings() {
    let headers = vec![H3Header::new("a", "www.example.com")];
    let mut fingerprint = Http3Fingerprint::chrome();
    fingerprint.stream.request_header_block_strategy = QpackHeaderBlockStrategy::LiteralOnly;
    fingerprint.stream.request_string_encoding = QpackStringEncodingStrategy::Huffman;

    let stream = encode_request_stream_with_fingerprint(&headers, None, &fingerprint);
    let frames = decode_frames(&stream).unwrap();
    let H3Frame::Headers(block) = &frames[0] else {
        panic!("first request-stream frame must be HEADERS");
    };

    assert_eq!(block[0], 0);
    assert_eq!(block[1], 0);
    assert_eq!(
        block[2] & 0x28,
        0x28,
        "literal name must carry the Huffman bit"
    );
    assert_eq!(
        block[4] & 0x80,
        0x80,
        "literal value must carry the Huffman bit"
    );
    assert_eq!(decode_header_block(block.as_ref()).unwrap(), headers);
}

#[test]
fn native_qpack_encodes_rfc9220_connect_pseudo_headers() {
    let uri: http::Uri = "https://example.test/chat".parse().unwrap();
    let headers = build_websocket_connect_headers(&uri, &[]).unwrap();

    let block = encode_header_block(&headers);
    let decoded = decode_header_block(&block).unwrap();

    assert_eq!(&decoded[..5], &headers[..5]);
    assert_eq!(decoded[0], H3Header::new(":method", "CONNECT"));
    assert_eq!(decoded[1], H3Header::new(":protocol", "websocket"));
}

#[test]
fn native_request_stream_encodes_headers_then_data_frames() {
    let uri: http::Uri = "https://example.test/upload".parse().unwrap();
    let headers = build_request_headers(
        &http::Method::POST,
        &uri,
        &[("content-type".into(), "text/plain".into())],
    )
    .unwrap();

    let stream = encode_request_stream(&headers, Some(Bytes::from_static(b"hello")));
    let frames = decode_frames(&stream).unwrap();

    assert_eq!(frames.len(), 2);
    let H3Frame::Headers(block) = &frames[0] else {
        panic!("first request-stream frame must be HEADERS");
    };
    assert_eq!(decode_header_block(block.as_ref()).unwrap(), headers);
    assert_eq!(frames[1], H3Frame::Data(Bytes::from_static(b"hello")));
}
