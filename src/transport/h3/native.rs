//! Native HTTP/3 frame and SETTINGS codec.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::{Error, Result};
use crate::headers::Headers;
use crate::fingerprint::{
    H3Settings, Http3Fingerprint, QpackHeaderBlockStrategy, QpackStringEncodingStrategy,
};
use crate::transport::h2::hpack_impl::{
    huffman_decode_bytes, huffman_encode_bytes, huffman_encode_if_smaller_bytes,
};

const FRAME_DATA: u64 = 0x0;
const FRAME_HEADERS: u64 = 0x1;
const FRAME_SETTINGS: u64 = 0x4;
const FRAME_GOAWAY: u64 = 0x7;
const FRAME_GREASE: u64 = 0x21;

const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x6;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x7;
const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x8;
const SETTINGS_GREASE: u64 = 0x21;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3Frame {
    Data(Bytes),
    Headers(Bytes),
    Settings(Vec<H3Setting>),
    GoAway { id: u64 },
    Unknown { frame_type: u64, payload: Bytes },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3Setting {
    QpackMaxTableCapacity(u64),
    MaxFieldSectionSize(u64),
    QpackBlockedStreams(u64),
    EnableConnectProtocol(u64),
    Additional(u64, u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum H3StreamType {
    Control,
    Push,
    QpackEncoder,
    QpackDecoder,
    Grease(u64),
    Unknown(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3UnidirectionalStream {
    pub stream_type: H3StreamType,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3Header {
    name: String,
    value: String,
}

pub(crate) fn data_frame_encoded_len(payload_len: usize) -> usize {
    varint_len(FRAME_DATA)
        .saturating_add(varint_len(payload_len as u64))
        .saturating_add(payload_len)
}

impl H3Header {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

pub fn encode_settings_payload(settings: &H3Settings) -> Vec<H3Setting> {
    if let Some(raw_settings) = &settings.raw_ordered_settings {
        return raw_settings
            .iter()
            .map(|(key, value)| h3_setting_from_wire_pair(*key, *value))
            .collect();
    }

    let mut payload = Vec::new();
    if let Some(value) = settings.qpack_max_table_capacity {
        payload.push(H3Setting::QpackMaxTableCapacity(value));
    }
    if let Some(value) = settings.qpack_blocked_streams {
        payload.push(H3Setting::QpackBlockedStreams(value));
    }
    if let Some(value) = settings.max_field_section_size {
        payload.push(H3Setting::MaxFieldSectionSize(value));
    }
    if settings.enable_extended_connect {
        payload.push(H3Setting::EnableConnectProtocol(1));
    }
    payload.extend(
        settings
            .additional_settings
            .iter()
            .map(|(key, value)| H3Setting::Additional(*key, *value)),
    );
    payload
}

fn h3_setting_from_wire_pair(key: u64, value: u64) -> H3Setting {
    match key {
        SETTINGS_QPACK_MAX_TABLE_CAPACITY => H3Setting::QpackMaxTableCapacity(value),
        SETTINGS_MAX_FIELD_SECTION_SIZE => H3Setting::MaxFieldSectionSize(value),
        SETTINGS_QPACK_BLOCKED_STREAMS => H3Setting::QpackBlockedStreams(value),
        SETTINGS_ENABLE_CONNECT_PROTOCOL => H3Setting::EnableConnectProtocol(value),
        _ => H3Setting::Additional(key, value),
    }
}

pub fn encode_fingerprint_settings_payload(fingerprint: &Http3Fingerprint) -> Vec<H3Setting> {
    let mut payload = encode_settings_payload(&fingerprint.settings);
    if fingerprint.stream.send_grease_frames
        && !payload.iter().any(
            |setting| matches!(setting, H3Setting::Additional(key, _) if *key == SETTINGS_GREASE),
        )
    {
        payload.push(H3Setting::Additional(SETTINGS_GREASE, 0));
    }
    payload
}

fn encode_control_stream_payload(fingerprint: &Http3Fingerprint) -> Bytes {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&encode_frame(&H3Frame::Settings(
        encode_fingerprint_settings_payload(fingerprint),
    )));
    if fingerprint.stream.send_grease_frames {
        payload.extend_from_slice(&encode_frame(&H3Frame::Unknown {
            frame_type: FRAME_GREASE,
            payload: Bytes::new(),
        }));
    }
    payload.freeze()
}

pub fn encode_client_preface_streams(
    fingerprint: &Http3Fingerprint,
) -> Vec<H3UnidirectionalStream> {
    let mut streams = Vec::new();
    let control_payload = encode_control_stream_payload(fingerprint);

    if fingerprint.stream.open_control_stream_first {
        streams.push(H3UnidirectionalStream {
            stream_type: H3StreamType::Control,
            payload: control_payload.clone(),
        });
    }

    let qpack_encoder = H3UnidirectionalStream {
        stream_type: H3StreamType::QpackEncoder,
        payload: Bytes::copy_from_slice(&fingerprint.stream.qpack_encoder_stream_payload),
    };
    let qpack_decoder = H3UnidirectionalStream {
        stream_type: H3StreamType::QpackDecoder,
        payload: Bytes::copy_from_slice(&fingerprint.stream.qpack_decoder_stream_payload),
    };

    if fingerprint.stream.open_qpack_encoder_before_decoder {
        streams.push(qpack_encoder);
        streams.push(qpack_decoder);
    } else {
        streams.push(qpack_decoder);
        streams.push(qpack_encoder);
    }

    if !fingerprint.stream.open_control_stream_first {
        streams.push(H3UnidirectionalStream {
            stream_type: H3StreamType::Control,
            payload: control_payload,
        });
    }

    if fingerprint.stream.send_grease_stream {
        streams.push(H3UnidirectionalStream {
            stream_type: H3StreamType::Grease(0x21),
            payload: Bytes::from_static(b"GREASE is the word"),
        });
    }

    streams
}

pub fn encode_unidirectional_stream(stream: &H3UnidirectionalStream) -> Bytes {
    let stream_type = encode_stream_type(stream.stream_type);
    let mut out = BytesMut::with_capacity(varint_len(stream_type) + stream.payload.len());
    put_varint(&mut out, stream_type);
    out.extend_from_slice(&stream.payload);
    out.freeze()
}

pub fn decode_unidirectional_stream(bytes: &[u8]) -> Result<H3UnidirectionalStream> {
    let mut input = Bytes::copy_from_slice(bytes);
    let stream_type = decode_stream_type(get_varint(&mut input)?);
    Ok(H3UnidirectionalStream {
        stream_type,
        payload: input,
    })
}

pub fn encode_frame(frame: &H3Frame) -> Bytes {
    let (frame_type, payload) = match frame {
        H3Frame::Data(data) => (FRAME_DATA, data.clone()),
        H3Frame::Headers(headers) => (FRAME_HEADERS, headers.clone()),
        H3Frame::Settings(settings) => (FRAME_SETTINGS, encode_settings(settings)),
        H3Frame::GoAway { id } => {
            let mut payload = BytesMut::new();
            put_varint(&mut payload, *id);
            (FRAME_GOAWAY, payload.freeze())
        }
        H3Frame::Unknown {
            frame_type,
            payload,
        } => (*frame_type, payload.clone()),
    };

    let mut out = BytesMut::with_capacity(
        varint_len(frame_type) + varint_len(payload.len() as u64) + payload.len(),
    );
    put_varint(&mut out, frame_type);
    put_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(&payload);
    out.freeze()
}

pub fn decode_frame(bytes: &[u8]) -> Result<H3Frame> {
    let mut input = Bytes::copy_from_slice(bytes);
    let frame_type = get_varint(&mut input)?;
    let len = get_varint(&mut input)? as usize;
    if input.remaining() < len {
        return Err(Error::HttpProtocol("truncated HTTP/3 frame".into()));
    }
    let payload = input.copy_to_bytes(len);

    match frame_type {
        FRAME_DATA => Ok(H3Frame::Data(payload)),
        FRAME_HEADERS => Ok(H3Frame::Headers(payload)),
        FRAME_SETTINGS => Ok(H3Frame::Settings(decode_settings(payload)?)),
        FRAME_GOAWAY => {
            let mut payload = payload;
            Ok(H3Frame::GoAway {
                id: get_varint(&mut payload)?,
            })
        }
        frame_type => Ok(H3Frame::Unknown {
            frame_type,
            payload,
        }),
    }
}

pub fn decode_frames(bytes: &[u8]) -> Result<Vec<H3Frame>> {
    let mut input = Bytes::copy_from_slice(bytes);
    let mut frames = Vec::new();
    while input.has_remaining() {
        let frame_type = get_varint(&mut input)?;
        let len = get_varint(&mut input)? as usize;
        if input.remaining() < len {
            return Err(Error::HttpProtocol("truncated HTTP/3 frame".into()));
        }
        let payload = input.copy_to_bytes(len);
        frames.push(decode_frame(&encode_frame_parts(frame_type, payload))?);
    }
    Ok(frames)
}

pub fn encode_request_stream(headers: &[H3Header], body: Option<Bytes>) -> Bytes {
    encode_request_stream_with_strategy(headers, body, QpackHeaderBlockStrategy::StaticThenLiteral)
}

pub fn encode_request_stream_with_fingerprint(
    headers: &[H3Header],
    body: Option<Bytes>,
    fingerprint: &Http3Fingerprint,
) -> Bytes {
    encode_request_stream_with_options(
        headers,
        body,
        fingerprint.stream.request_header_block_strategy,
        fingerprint.stream.request_string_encoding,
    )
}

fn encode_request_stream_with_strategy(
    headers: &[H3Header],
    body: Option<Bytes>,
    strategy: QpackHeaderBlockStrategy,
) -> Bytes {
    encode_request_stream_with_options(headers, body, strategy, QpackStringEncodingStrategy::Plain)
}

fn encode_request_stream_with_options(
    headers: &[H3Header],
    body: Option<Bytes>,
    strategy: QpackHeaderBlockStrategy,
    string_strategy: QpackStringEncodingStrategy,
) -> Bytes {
    let mut out = BytesMut::new();
    out.extend_from_slice(&encode_frame(&H3Frame::Headers(
        encode_header_block_with_options(headers, strategy, string_strategy),
    )));
    if let Some(body) = body {
        if !body.is_empty() {
            out.extend_from_slice(&encode_frame(&H3Frame::Data(body)));
        }
    }
    out.freeze()
}

pub fn build_websocket_connect_headers(
    uri: &http::Uri,
    headers: &[(String, String)],
) -> Result<Vec<H3Header>> {
    let scheme = uri.scheme_str().ok_or_else(|| {
        Error::WebSocketUnsupported("RFC 9220 requires an https URI internally".into())
    })?;
    if scheme != "https" {
        return Err(Error::WebSocketUnsupported(
            "RFC 9220 WebSocket over HTTP/3 requires wss://".into(),
        ));
    }

    let authority = uri
        .authority()
        .ok_or_else(|| Error::HttpProtocol("RFC 9220 CONNECT requires :authority".into()))?
        .as_str();
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let mut h3_headers = vec![
        H3Header::new(":method", "CONNECT"),
        H3Header::new(":protocol", "websocket"),
        H3Header::new(":scheme", scheme),
        H3Header::new(":path", path),
        H3Header::new(":authority", authority),
    ];

    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if name.starts_with(':') {
            return Err(Error::HttpProtocol(format!(
                "user pseudo-header {name} is not allowed on RFC 9220 CONNECT"
            )));
        }

        if matches!(
            lower.as_str(),
            "connection"
                | "upgrade"
                | "host"
                | "sec-websocket-key"
                | "sec-websocket-accept"
                | "sec-websocket-extensions"
        ) {
            return Err(Error::WebSocketUnsupported(format!(
                "header {name} is not allowed on RFC 9220 WebSocket over HTTP/3"
            )));
        }

        if matches!(
            lower.as_str(),
            "keep-alive" | "proxy-connection" | "transfer-encoding"
        ) {
            continue;
        }

        h3_headers.push(H3Header::new(lower, value));
    }

    Ok(h3_headers)
}

pub fn build_request_headers(
    method: &http::Method,
    uri: &http::Uri,
    headers: &Headers,
) -> Result<Vec<H3Header>> {
    let scheme = uri.scheme_str().unwrap_or("https");
    let authority = uri
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| uri.host())
        .unwrap_or("");
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let mut h3_headers = vec![
        H3Header::new(":method", method.as_str()),
        H3Header::new(":scheme", scheme),
        H3Header::new(":authority", authority),
        H3Header::new(":path", path),
    ];

    for (name, value) in headers.iter_bytes() {
        let lower = if name.iter().all(|b| b.is_ascii_lowercase()) {
            String::from_utf8_lossy(name).into_owned()
        } else {
            name.iter().map(|b| b.to_ascii_lowercase() as char).collect()
        };
        if name.first() != Some(&b':')
            && lower != "connection"
            && lower != "keep-alive"
            && lower != "proxy-connection"
            && lower != "transfer-encoding"
            && lower != "upgrade"
        {
            h3_headers.push(H3Header::new(
                lower,
                String::from_utf8_lossy(value).into_owned(),
            ));
        }
    }

    Ok(h3_headers)
}

pub fn encode_header_block(headers: &[H3Header]) -> Bytes {
    encode_header_block_with_strategy(headers, QpackHeaderBlockStrategy::StaticThenLiteral)
}

pub fn encode_header_block_with_strategy(
    headers: &[H3Header],
    strategy: QpackHeaderBlockStrategy,
) -> Bytes {
    encode_header_block_with_options(headers, strategy, QpackStringEncodingStrategy::Plain)
}

fn encode_header_block_with_options(
    headers: &[H3Header],
    strategy: QpackHeaderBlockStrategy,
    string_strategy: QpackStringEncodingStrategy,
) -> Bytes {
    let mut out = BytesMut::new();
    put_prefixed_int(&mut out, 0, 0, 8);
    put_prefixed_int(&mut out, 0, 0, 7);

    for header in headers {
        if strategy == QpackHeaderBlockStrategy::StaticThenLiteral {
            if let Some((index, exact)) = static_lookup(header.name(), header.value()) {
                if exact {
                    put_prefixed_int(&mut out, index, 0xc0, 6);
                } else {
                    put_prefixed_int(&mut out, index, 0x50, 4);
                    put_prefixed_string_with_strategy(
                        &mut out,
                        header.value().as_bytes(),
                        0,
                        7,
                        string_strategy,
                    );
                }
                continue;
            }
        }
        put_prefixed_string_with_strategy(
            &mut out,
            header.name().as_bytes(),
            0x20,
            3,
            string_strategy,
        );
        put_prefixed_string_with_strategy(
            &mut out,
            header.value().as_bytes(),
            0,
            7,
            string_strategy,
        );
    }

    out.freeze()
}

pub fn decode_header_block(bytes: &[u8]) -> Result<Vec<H3Header>> {
    let mut input = Bytes::copy_from_slice(bytes);
    let first = get_byte(&mut input)?;
    let _required_insert_count = get_prefixed_int(first, 8, &mut input)?;
    let first = get_byte(&mut input)?;
    let _delta_base = get_prefixed_int(first, 7, &mut input)?;

    let mut headers = Vec::new();
    while input.has_remaining() {
        let first = get_byte(&mut input)?;
        if first & 0x80 != 0 {
            if first & 0x40 == 0 {
                return Err(Error::HttpProtocol(
                    "native QPACK decoder only supports static indexed fields".into(),
                ));
            }
            let index = get_prefixed_int(first, 6, &mut input)?;
            let (name, value) = static_by_index(index).ok_or_else(|| {
                Error::HttpProtocol(format!("unknown QPACK static index {index}"))
            })?;
            headers.push(H3Header::new(name, value));
        } else if first & 0x40 != 0 {
            if first & 0x10 == 0 {
                return Err(Error::HttpProtocol(
                    "native QPACK decoder only supports static name refs".into(),
                ));
            }
            let index = get_prefixed_int(first, 4, &mut input)?;
            let (name, _) = static_by_index(index).ok_or_else(|| {
                Error::HttpProtocol(format!("unknown QPACK static index {index}"))
            })?;
            let value = get_prefixed_string(&mut input, 7)?;
            headers.push(H3Header::new(name, value));
        } else if first & 0x20 != 0 {
            let name = get_prefixed_string_with_first(first, 3, &mut input)?;
            let value = get_prefixed_string(&mut input, 7)?;
            headers.push(H3Header::new(name, value));
        } else {
            return Err(Error::HttpProtocol(
                "unsupported native QPACK field representation".into(),
            ));
        }
    }

    Ok(headers)
}

fn encode_stream_type(stream_type: H3StreamType) -> u64 {
    match stream_type {
        H3StreamType::Control => 0x00,
        H3StreamType::Push => 0x01,
        H3StreamType::QpackEncoder => 0x02,
        H3StreamType::QpackDecoder => 0x03,
        H3StreamType::Grease(value) | H3StreamType::Unknown(value) => value,
    }
}

fn decode_stream_type(stream_type: u64) -> H3StreamType {
    match stream_type {
        0x00 => H3StreamType::Control,
        0x01 => H3StreamType::Push,
        0x02 => H3StreamType::QpackEncoder,
        0x03 => H3StreamType::QpackDecoder,
        value if value % 0x1f == 0x21 % 0x1f => H3StreamType::Grease(value),
        value => H3StreamType::Unknown(value),
    }
}

fn encode_settings(settings: &[H3Setting]) -> Bytes {
    let mut out = BytesMut::new();
    for setting in settings {
        let (key, value) = match setting {
            H3Setting::QpackMaxTableCapacity(value) => (SETTINGS_QPACK_MAX_TABLE_CAPACITY, *value),
            H3Setting::MaxFieldSectionSize(value) => (SETTINGS_MAX_FIELD_SECTION_SIZE, *value),
            H3Setting::QpackBlockedStreams(value) => (SETTINGS_QPACK_BLOCKED_STREAMS, *value),
            H3Setting::EnableConnectProtocol(value) => (SETTINGS_ENABLE_CONNECT_PROTOCOL, *value),
            H3Setting::Additional(key, value) => (*key, *value),
        };
        put_varint(&mut out, key);
        put_varint(&mut out, value);
    }
    out.freeze()
}

fn encode_frame_parts(frame_type: u64, payload: Bytes) -> Bytes {
    let mut out = BytesMut::with_capacity(
        varint_len(frame_type) + varint_len(payload.len() as u64) + payload.len(),
    );
    put_varint(&mut out, frame_type);
    put_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(&payload);
    out.freeze()
}

fn decode_settings(mut payload: Bytes) -> Result<Vec<H3Setting>> {
    let mut settings = Vec::new();
    while payload.has_remaining() {
        let key = get_varint(&mut payload)?;
        let value = get_varint(&mut payload)?;
        settings.push(match key {
            SETTINGS_QPACK_MAX_TABLE_CAPACITY => H3Setting::QpackMaxTableCapacity(value),
            SETTINGS_MAX_FIELD_SECTION_SIZE => H3Setting::MaxFieldSectionSize(value),
            SETTINGS_QPACK_BLOCKED_STREAMS => H3Setting::QpackBlockedStreams(value),
            SETTINGS_ENABLE_CONNECT_PROTOCOL => H3Setting::EnableConnectProtocol(value),
            key => H3Setting::Additional(key, value),
        });
    }
    Ok(settings)
}

fn put_varint(out: &mut BytesMut, value: u64) {
    match value {
        0..=0x3f => out.put_u8(value as u8),
        0x40..=0x3fff => out.put_u16((value as u16) | 0x4000),
        0x4000..=0x3fff_ffff => out.put_u32((value as u32) | 0x8000_0000),
        _ => out.put_u64(value | 0xc000_0000_0000_0000),
    }
}

fn static_lookup(name: &str, value: &str) -> Option<(u64, bool)> {
    let lower_name = name.to_ascii_lowercase();
    for (index, static_name, static_value) in STATIC_TABLE {
        if *static_name == lower_name {
            if static_value.is_empty() {
                return Some((*index, false));
            }
            if *static_value == value {
                return Some((*index, true));
            }
        }
    }
    None
}

fn static_by_index(index: u64) -> Option<(&'static str, &'static str)> {
    STATIC_TABLE
        .iter()
        .find_map(|(entry_index, name, value)| (*entry_index == index).then_some((*name, *value)))
}

const STATIC_TABLE: &[(u64, &str, &str)] = &[
    (0, ":authority", ""),
    (1, ":path", "/"),
    (15, ":method", "CONNECT"),
    (16, ":method", "DELETE"),
    (17, ":method", "GET"),
    (18, ":method", "HEAD"),
    (19, ":method", "OPTIONS"),
    (20, ":method", "POST"),
    (21, ":method", "PUT"),
    (22, ":scheme", "http"),
    (23, ":scheme", "https"),
    (24, ":status", "103"),
    (25, ":status", "200"),
    (26, ":status", "304"),
    (27, ":status", "404"),
    (28, ":status", "503"),
    (29, "accept", "*/*"),
    (53, "content-type", "text/plain"),
    (55, "range", "bytes=0-"),
    (95, "user-agent", ""),
];

fn put_prefixed_string_with_strategy(
    out: &mut BytesMut,
    value: &[u8],
    first: u8,
    prefix: usize,
    strategy: QpackStringEncodingStrategy,
) {
    let (encoded, huffman) = match strategy {
        QpackStringEncodingStrategy::Plain => (value.to_vec(), false),
        QpackStringEncodingStrategy::Huffman => (huffman_encode_bytes(value), true),
        QpackStringEncodingStrategy::HuffmanIfSmaller => huffman_encode_if_smaller_bytes(value),
    };
    let huffman_bit = if huffman { 1u8 << prefix } else { 0 };
    put_prefixed_int(out, encoded.len() as u64, first | huffman_bit, prefix);
    out.extend_from_slice(&encoded);
}

fn put_prefixed_int(out: &mut BytesMut, mut value: u64, first: u8, prefix: usize) {
    let mask = (1u64 << prefix) - 1;
    if value < mask {
        out.put_u8(first | value as u8);
        return;
    }

    out.put_u8(first | mask as u8);
    value -= mask;
    while value >= 128 {
        out.put_u8((value % 128 + 128) as u8);
        value >>= 7;
    }
    out.put_u8(value as u8);
}

fn get_byte(input: &mut Bytes) -> Result<u8> {
    if !input.has_remaining() {
        return Err(Error::HttpProtocol("truncated QPACK header block".into()));
    }
    Ok(input.get_u8())
}

fn get_prefixed_string(input: &mut Bytes, prefix: usize) -> Result<String> {
    let first = get_byte(input)?;
    get_prefixed_string_with_first(first, prefix, input)
}

fn get_prefixed_string_with_first(first: u8, prefix: usize, input: &mut Bytes) -> Result<String> {
    let huffman = first & (1 << prefix) != 0;
    let len = get_prefixed_int(first, prefix, input)? as usize;
    if input.remaining() < len {
        return Err(Error::HttpProtocol("truncated QPACK string".into()));
    }
    let value = input.copy_to_bytes(len);
    let decoded = if huffman {
        huffman_decode_bytes(value.as_ref())
            .map_err(|err| Error::HttpProtocol(format!("invalid QPACK Huffman string: {err}")))?
    } else {
        value.to_vec()
    };
    String::from_utf8(decoded)
        .map_err(|e| Error::HttpProtocol(format!("invalid QPACK string utf8: {e}")))
}

fn get_prefixed_int(first: u8, prefix: usize, input: &mut Bytes) -> Result<u64> {
    let mask = (1u64 << prefix) - 1;
    let mut value = (first as u64) & mask;
    if value < mask {
        return Ok(value);
    }

    let mut shift = 0;
    loop {
        let byte = get_byte(input)?;
        value += ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 56 {
            return Err(Error::HttpProtocol("QPACK integer overflow".into()));
        }
    }
}

fn get_varint(input: &mut Bytes) -> Result<u64> {
    if !input.has_remaining() {
        return Err(Error::HttpProtocol("missing HTTP/3 varint".into()));
    }
    let first = input[0];
    let prefix = first >> 6;
    let len = 1usize << prefix;
    if input.remaining() < len {
        return Err(Error::HttpProtocol("truncated HTTP/3 varint".into()));
    }

    let value = match len {
        1 => input.get_u8() as u64 & 0x3f,
        2 => input.get_u16() as u64 & 0x3fff,
        4 => input.get_u32() as u64 & 0x3fff_ffff,
        8 => input.get_u64() & 0x3fff_ffff_ffff_ffff,
        _ => unreachable!(),
    };
    Ok(value)
}

fn varint_len(value: u64) -> usize {
    match value {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}
