//! gRPC length-prefixed message framing codec.
//!
//! Pure bytes-in / bytes-out codec over [`Bytes`]. It is deliberately
//! decoupled from `Body`/`H2Body`: feed it chunks with [`GrpcFramer::push`]
//! and drain complete messages with [`GrpcFramer::next_message`]. No protobuf
//! parsing, no `.proto` codegen.
//!
//! ## Wire format
//!
//! Each gRPC message on the wire is:
//!
//! ```text
//! [1 byte compression flag][4 bytes big-endian uint32 length][length bytes payload]
//! ```
//!
//! A single DATA chunk may contain many messages, and one message may span
//! multiple chunks. The compression flag is **per message**: `0` means the
//! payload is identity-coded (passthrough even when the stream advertises
//! `grpc-encoding: gzip`), `1` means the payload is compressed with the
//! stream's encoding.
//!
//! ## Zero-copy
//!
//! When a full `[flag][len][payload]` frame lives within a single pushed chunk
//! and the carry buffer is empty, the payload is extracted with
//! [`Bytes::slice`] (a refcount bump, no memcpy). When a frame straddles chunk
//! boundaries, or the carry buffer already holds a partial frame, the bytes are
//! copied into the carry buffer to reassemble it.

use bytes::{BufMut, Bytes, BytesMut};
use std::io::Read;

use crate::error::{Error, Result};

/// Number of header bytes preceding every message payload: one compression
/// flag byte plus a 4-byte big-endian length.
const HEADER_LEN: usize = 5;

/// Per-stream message encoding negotiated via the `grpc-encoding` header.
///
/// The compression flag byte on each message selects identity vs. this
/// encoding on a per-message basis; see [`GrpcFramer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrpcEncoding {
    /// No compression. A message flagged compressed under this encoding is a
    /// protocol error.
    Identity,
    /// gzip compression (reuses `flate2`, the same decoder HTTP responses use).
    Gzip,
}

/// Incremental decoder for gRPC length-prefixed messages.
///
/// Push raw [`Bytes`] chunks as they arrive off the body, then repeatedly call
/// [`next_message`](GrpcFramer::next_message) until it returns `Ok(None)` to
/// drain every fully-available message.
#[derive(Debug)]
pub struct GrpcFramer {
    encoding: GrpcEncoding,
    /// Holds an incomplete prefix/payload carried across chunk boundaries.
    /// Empty whenever the framer is positioned exactly at a message boundary.
    carry: BytesMut,
    /// The most recently pushed chunk, consumed in place so contained messages
    /// can be sliced zero-copy. Bytes that begin an incomplete trailing frame
    /// are moved into `carry` before the next push.
    chunk: Bytes,
}

impl GrpcFramer {
    /// Create a framer for the given stream encoding.
    pub fn new(encoding: GrpcEncoding) -> Self {
        Self {
            encoding,
            carry: BytesMut::new(),
            chunk: Bytes::new(),
        }
    }

    /// The negotiated stream encoding.
    pub fn encoding(&self) -> GrpcEncoding {
        self.encoding
    }

    /// Append an incoming chunk.
    ///
    /// If a previous chunk left an incomplete trailing frame, that remainder is
    /// already sitting in `carry`; pushing here either keeps reading from the
    /// current `chunk` (when it has not been fully consumed) or replaces it.
    /// The common steady state - `next_message` having drained the prior chunk
    /// to a boundary - keeps `chunk` empty and lets the new chunk be sliced
    /// directly.
    pub fn push(&mut self, chunk: Bytes) {
        if self.chunk.is_empty() {
            self.chunk = chunk;
        } else {
            // Rare: caller pushed again before draining. Spill the remaining
            // current chunk into carry, then adopt the new chunk.
            self.carry.extend_from_slice(&self.chunk);
            self.chunk = Bytes::new();
            self.carry.extend_from_slice(&chunk);
        }
    }

    /// Return the next fully-available, decompressed message payload, or
    /// `None` if more bytes are needed. Drain in a loop until `None`.
    pub fn next_message(&mut self) -> Result<Option<Bytes>> {
        // Fast path: carry is empty and the whole frame is contained in the
        // current chunk. Slice the payload zero-copy.
        if self.carry.is_empty() {
            return self.next_from_chunk();
        }
        self.next_from_carry()
    }

    /// Contained-message path: `carry` is empty, so attempt to read a full
    /// frame directly out of `self.chunk` using zero-copy slices.
    fn next_from_chunk(&mut self) -> Result<Option<Bytes>> {
        if self.chunk.len() < HEADER_LEN {
            // Not even a full header. Move the straggler into carry and wait.
            if !self.chunk.is_empty() {
                self.carry.extend_from_slice(&self.chunk);
                self.chunk = Bytes::new();
            }
            return Ok(None);
        }

        let flag = self.chunk[0];
        let len = u32::from_be_bytes([self.chunk[1], self.chunk[2], self.chunk[3], self.chunk[4]])
            as usize;
        let total = HEADER_LEN + len;

        if self.chunk.len() < total {
            // Header is here but the payload is incomplete: this frame spans
            // chunks. Spill the partial frame into carry to reassemble later.
            self.carry.extend_from_slice(&self.chunk);
            self.chunk = Bytes::new();
            return Ok(None);
        }

        // Full frame is contained. Zero-copy slice for the payload, then
        // advance the chunk past this frame.
        let payload = self.chunk.slice(HEADER_LEN..total);
        self.chunk = self.chunk.slice(total..);
        self.decode_payload(flag, payload).map(Some)
    }

    /// Chunk-spanning path: a partial frame already lives in `carry`. Pull from
    /// the current chunk to complete it. This path copies (the reassembly is
    /// the whole reason carry exists).
    fn next_from_carry(&mut self) -> Result<Option<Bytes>> {
        // Top up carry from the current chunk so we can decide if a full frame
        // is now present. We only need enough to read the header, then the full
        // payload; pull lazily to avoid copying more than necessary.
        if self.carry.len() < HEADER_LEN {
            let need = HEADER_LEN - self.carry.len();
            self.drain_chunk_into_carry(need);
            if self.carry.len() < HEADER_LEN {
                return Ok(None);
            }
        }

        let flag = self.carry[0];
        let len = u32::from_be_bytes([self.carry[1], self.carry[2], self.carry[3], self.carry[4]])
            as usize;
        let total = HEADER_LEN + len;

        if self.carry.len() < total {
            let need = total - self.carry.len();
            self.drain_chunk_into_carry(need);
            if self.carry.len() < total {
                return Ok(None);
            }
        }

        // Full frame reassembled in carry. Split off the payload and drop the
        // header. `split_to` keeps the remainder (start of the next frame) in
        // carry for the following call.
        let mut frame = self.carry.split_to(total);
        let _header = frame.split_to(HEADER_LEN);
        let payload = frame.freeze();

        // If carry is now empty, the next message (if any) can resume the
        // zero-copy contained path against the current chunk.
        self.decode_payload(flag, payload).map(Some)
    }

    /// Move up to `need` bytes from the front of `self.chunk` into `carry`.
    fn drain_chunk_into_carry(&mut self, need: usize) {
        if self.chunk.is_empty() || need == 0 {
            return;
        }
        let take = need.min(self.chunk.len());
        let moved = self.chunk.slice(..take);
        self.carry.extend_from_slice(&moved);
        self.chunk = self.chunk.slice(take..);
    }

    /// Apply the per-message compression flag and stream encoding to a raw
    /// payload.
    fn decode_payload(&self, flag: u8, payload: Bytes) -> Result<Bytes> {
        match flag {
            0 => Ok(payload),
            1 => match self.encoding {
                GrpcEncoding::Gzip => gunzip(&payload),
                GrpcEncoding::Identity => Err(Error::HttpProtocol(
                    "gRPC message flagged compressed but stream encoding is identity".to_string(),
                )),
            },
            other => Err(Error::HttpProtocol(format!(
                "invalid gRPC compression flag: {}",
                other
            ))),
        }
    }
}

/// Decompress a gzip-coded gRPC message payload. Mirrors the `flate2`
/// `GzDecoder` idiom used for HTTP responses (`response.rs` `decode_gzip`).
fn gunzip(payload: &[u8]) -> Result<Bytes> {
    let mut decoder = flate2::read::GzDecoder::new(payload);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| Error::Decompression(format!("gRPC gzip: {}", e)))?;
    Ok(Bytes::from(out))
}

/// Encode a single gRPC message: prepend the compression flag and big-endian
/// length, optionally gzip-compressing the payload first.
///
/// `compress` only takes effect with [`GrpcEncoding::Gzip`]; with
/// [`GrpcEncoding::Identity`] the payload is always written flag `0`.
pub fn encode_message(payload: &[u8], compress: bool, encoding: GrpcEncoding) -> Result<Bytes> {
    let (flag, body): (u8, std::borrow::Cow<'_, [u8]>) = if compress {
        match encoding {
            GrpcEncoding::Gzip => (1, std::borrow::Cow::Owned(gzip(payload)?)),
            GrpcEncoding::Identity => (0, std::borrow::Cow::Borrowed(payload)),
        }
    } else {
        (0, std::borrow::Cow::Borrowed(payload))
    };

    let len: u32 = body
        .len()
        .try_into()
        .map_err(|_| Error::HttpProtocol("gRPC message exceeds u32 length".to_string()))?;

    let mut buf = BytesMut::with_capacity(HEADER_LEN + body.len());
    buf.put_u8(flag);
    buf.put_u32(len); // big-endian
    buf.put_slice(&body);
    Ok(buf.freeze())
}

/// gzip-compress a payload for [`encode_message`]. Returns an owned `Vec<u8>`
/// so the encoder can carry it in a `Cow` alongside the borrowed identity path.
fn gzip(payload: &[u8]) -> Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(payload)
        .map_err(|e| Error::Decompression(format!("gRPC gzip encode: {}", e)))?;
    encoder
        .finish()
        .map_err(|e| Error::Decompression(format!("gRPC gzip finish: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a raw identity-coded frame: flag 0, big-endian len, payload.
    fn frame_identity(payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER_LEN + payload.len());
        v.push(0);
        v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// Drain every available message from the framer into a Vec.
    fn drain(framer: &mut GrpcFramer) -> Vec<Bytes> {
        let mut out = Vec::new();
        while let Some(m) = framer.next_message().expect("decode") {
            out.push(m);
        }
        out
    }

    // (a) multiple messages packed in one chunk.
    #[test]
    fn multiple_messages_one_chunk() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&frame_identity(b"hello"));
        wire.extend_from_slice(&frame_identity(b"world"));
        wire.extend_from_slice(&frame_identity(b"!"));

        let mut framer = GrpcFramer::new(GrpcEncoding::Identity);
        framer.push(Bytes::from(wire));
        let msgs = drain(&mut framer);
        assert_eq!(msgs.len(), 3);
        assert_eq!(&msgs[0][..], b"hello");
        assert_eq!(&msgs[1][..], b"world");
        assert_eq!(&msgs[2][..], b"!");
    }

    // (b) one message split across N chunks - byte-by-byte.
    #[test]
    fn message_split_byte_by_byte() {
        let payload = b"the quick brown fox jumps over the lazy dog";
        let wire = frame_identity(payload);

        let mut framer = GrpcFramer::new(GrpcEncoding::Identity);
        let mut got = Vec::new();
        for b in &wire {
            framer.push(Bytes::copy_from_slice(&[*b]));
            while let Some(m) = framer.next_message().expect("decode") {
                got.push(m);
            }
        }
        assert_eq!(got.len(), 1);
        assert_eq!(&got[0][..], &payload[..]);
    }

    // (b) one message split across N chunks - odd-sized slices.
    #[test]
    fn message_split_odd_sized_slices() {
        let payload = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let mut wire = Vec::new();
        wire.extend_from_slice(&frame_identity(&payload[..10]));
        wire.extend_from_slice(&frame_identity(&payload[10..]));

        let mut framer = GrpcFramer::new(GrpcEncoding::Identity);
        let mut got = Vec::new();
        // Feed in irregular 7-byte slices.
        for window in wire.chunks(7) {
            framer.push(Bytes::copy_from_slice(window));
            while let Some(m) = framer.next_message().expect("decode") {
                got.push(m);
            }
        }
        assert_eq!(got.len(), 2);
        assert_eq!(&got[0][..], &payload[..10]);
        assert_eq!(&got[1][..], &payload[10..]);
    }

    // (c) zero-length payloads.
    #[test]
    fn zero_length_payloads() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&frame_identity(b""));
        wire.extend_from_slice(&frame_identity(b"x"));
        wire.extend_from_slice(&frame_identity(b""));

        let mut framer = GrpcFramer::new(GrpcEncoding::Identity);
        framer.push(Bytes::from(wire));
        let msgs = drain(&mut framer);
        assert_eq!(msgs.len(), 3);
        assert_eq!(&msgs[0][..], b"");
        assert_eq!(&msgs[1][..], b"x");
        assert_eq!(&msgs[2][..], b"");
    }

    // (d) trailing partial prefix (only 3 of 5 header bytes) completing next chunk.
    #[test]
    fn partial_prefix_completes_next_chunk() {
        let payload = b"payload-bytes";
        let wire = frame_identity(payload);

        let mut framer = GrpcFramer::new(GrpcEncoding::Identity);
        // First chunk: 3 of 5 header bytes only.
        framer.push(Bytes::copy_from_slice(&wire[..3]));
        assert!(framer.next_message().expect("decode").is_none());
        // Second chunk: the rest.
        framer.push(Bytes::copy_from_slice(&wire[3..]));
        let msgs = drain(&mut framer);
        assert_eq!(msgs.len(), 1);
        assert_eq!(&msgs[0][..], &payload[..]);
    }

    // (e) identity flag-0 passthrough even when stream encoding is gzip.
    #[test]
    fn identity_flag_passthrough_under_gzip_stream() {
        let payload = b"not actually compressed";
        let wire = frame_identity(payload); // flag 0

        let mut framer = GrpcFramer::new(GrpcEncoding::Gzip);
        framer.push(Bytes::from(wire));
        let msgs = drain(&mut framer);
        assert_eq!(msgs.len(), 1);
        assert_eq!(&msgs[0][..], &payload[..]);
    }

    // (f) gzip flag-1 round-trip.
    #[test]
    fn gzip_flag_round_trip() {
        let payload = b"compress me, then decompress me back to exactly this";
        let encoded = encode_message(payload, true, GrpcEncoding::Gzip).expect("encode");
        // Sanity: flag byte is 1 and the body differs from raw payload.
        assert_eq!(encoded[0], 1);

        let mut framer = GrpcFramer::new(GrpcEncoding::Gzip);
        framer.push(encoded);
        let msgs = drain(&mut framer);
        assert_eq!(msgs.len(), 1);
        assert_eq!(&msgs[0][..], &payload[..]);
    }

    // (g) flag-1 + Identity encoding -> Err (protocol error).
    #[test]
    fn compressed_flag_under_identity_is_error() {
        let mut wire = Vec::new();
        wire.push(1); // compressed flag
        wire.extend_from_slice(&(3u32).to_be_bytes());
        wire.extend_from_slice(b"abc");

        let mut framer = GrpcFramer::new(GrpcEncoding::Identity);
        framer.push(Bytes::from(wire));
        assert!(framer.next_message().is_err());
    }

    // (h) bogus flag -> Err.
    #[test]
    fn bogus_flag_is_error() {
        let mut wire = Vec::new();
        wire.push(7); // neither 0 nor 1
        wire.extend_from_slice(&(2u32).to_be_bytes());
        wire.extend_from_slice(b"hi");

        let mut framer = GrpcFramer::new(GrpcEncoding::Gzip);
        framer.push(Bytes::from(wire));
        assert!(framer.next_message().is_err());
    }

    // encode -> decode round-trip for the identity (uncompressed) path.
    #[test]
    fn encode_decode_identity_round_trip() {
        let payload = b"round trip identity";
        let encoded = encode_message(payload, false, GrpcEncoding::Identity).expect("encode");
        assert_eq!(encoded[0], 0);
        assert_eq!(
            u32::from_be_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]) as usize,
            payload.len()
        );

        let mut framer = GrpcFramer::new(GrpcEncoding::Identity);
        framer.push(encoded);
        let msgs = drain(&mut framer);
        assert_eq!(msgs.len(), 1);
        assert_eq!(&msgs[0][..], &payload[..]);
    }

    // encode with compress=true but Identity encoding stays flag 0 / passthrough.
    #[test]
    fn encode_compress_under_identity_is_passthrough() {
        let payload = b"identity ignores compress flag";
        let encoded = encode_message(payload, true, GrpcEncoding::Identity).expect("encode");
        assert_eq!(encoded[0], 0);

        let mut framer = GrpcFramer::new(GrpcEncoding::Identity);
        framer.push(encoded);
        let msgs = drain(&mut framer);
        assert_eq!(&msgs[0][..], &payload[..]);
    }

    // Two messages where the SECOND spans the boundary after the first is
    // sliced zero-copy from the same chunk - exercises carry re-entry.
    #[test]
    fn second_message_spans_after_contained_first() {
        let mut first_chunk = Vec::new();
        first_chunk.extend_from_slice(&frame_identity(b"first"));
        // Start the second frame but cut it mid-payload.
        let second = frame_identity(b"second-message");
        first_chunk.extend_from_slice(&second[..8]);

        let mut framer = GrpcFramer::new(GrpcEncoding::Identity);
        framer.push(Bytes::from(first_chunk));
        let mut got = drain(&mut framer);
        assert_eq!(got.len(), 1);
        assert_eq!(&got[0][..], b"first");

        framer.push(Bytes::copy_from_slice(&second[8..]));
        got.extend(drain(&mut framer));
        assert_eq!(got.len(), 2);
        assert_eq!(&got[1][..], b"second-message");
    }
}
