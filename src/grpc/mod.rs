//! Opt-in gRPC support, gated behind the `grpc` Cargo feature.
//!
//! This module is bytes-in / bytes-out: it provides a length-prefix message
//! framing codec ([`codec`]) over `Bytes`. There is no protobuf/prost/tonic
//! dependency and no `.proto` codegen. The default build never compiles this
//! module.
//!
//! Phase 2 ships the framing codec only. A later phase will add a gRPC request
//! constructor here.

pub mod codec;

pub use codec::{encode_message, GrpcEncoding, GrpcFramer};
