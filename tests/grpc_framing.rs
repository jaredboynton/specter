//! Integration test exercising the PUBLIC `specter::grpc` framing API.
//!
//! Proves the codec is reachable through the crate's public surface (not just
//! the in-module unit tests). The `just test` recipe builds with
//! `--all-features`, so the `grpc` feature is active here; under a build
//! without it this file compiles to nothing.

#![cfg(feature = "grpc")]

use bytes::Bytes;
use specter::grpc::{encode_message, GrpcEncoding, GrpcFramer};

fn drain(framer: &mut GrpcFramer) -> Vec<Bytes> {
    let mut out = Vec::new();
    while let Some(m) = framer.next_message().expect("decode") {
        out.push(m);
    }
    out
}

#[test]
fn public_api_identity_round_trip() {
    let m1 = encode_message(b"hello", false, GrpcEncoding::Identity).expect("encode");
    let m2 = encode_message(b"world", false, GrpcEncoding::Identity).expect("encode");

    let mut framer = GrpcFramer::new(GrpcEncoding::Identity);
    // Push both messages in a single chunk to prove coalescing across the
    // public boundary.
    let mut joined = Vec::new();
    joined.extend_from_slice(&m1);
    joined.extend_from_slice(&m2);
    framer.push(Bytes::from(joined));

    let msgs = drain(&mut framer);
    assert_eq!(msgs.len(), 2);
    assert_eq!(&msgs[0][..], b"hello");
    assert_eq!(&msgs[1][..], b"world");
}

#[test]
fn public_api_gzip_round_trip_split_chunks() {
    let payload = b"a longer gRPC message body that benefits from gzip compression";
    let encoded = encode_message(payload, true, GrpcEncoding::Gzip).expect("encode");

    let mut framer = GrpcFramer::new(GrpcEncoding::Gzip);
    // Feed the encoded frame in two pieces so it spans the carry buffer.
    let split = encoded.len() / 2;
    framer.push(encoded.slice(..split));
    assert!(framer.next_message().expect("decode").is_none());
    framer.push(encoded.slice(split..));

    let msgs = drain(&mut framer);
    assert_eq!(msgs.len(), 1);
    assert_eq!(&msgs[0][..], &payload[..]);
}
