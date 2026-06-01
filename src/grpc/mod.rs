//! Opt-in gRPC support, gated behind the `grpc` Cargo feature.
//!
//! This module is bytes-in / bytes-out: it provides a length-prefix message
//! framing codec ([`codec`]) over `Bytes`. There is no protobuf/prost/tonic
//! dependency and no `.proto` codegen. The default build never compiles this
//! module.
//!
//! Phase 2 ships the framing codec ([`codec`]). Phase 3 adds [`grpc_request`],
//! a fingerprint-safe gRPC request constructor.

pub mod codec;

pub use codec::{encode_message, GrpcEncoding, GrpcFramer};

use crate::request::IntoUrl;
use crate::transport::h1_h2::{Client, RequestBuilder};

/// Construct a fingerprint-safe gRPC request builder.
///
/// Returns a [`RequestBuilder`] preconfigured as a gRPC unary/streaming call:
/// `POST` to the given `url` (whose path must already be `/package.Service/Method`,
/// e.g. `/helloworld.Greeter/SayHello`), with the gRPC regular headers set in the
/// order gRPC peers expect them on the wire.
///
/// This is bytes-in / bytes-out. It sets method, path, and headers only; it does
/// **not** attach a body. The caller frames the request payload with
/// [`encode_message`] and calls [`RequestBuilder::body`] /
/// [`RequestBuilder::body_stream`], then [`RequestBuilder::send`] /
/// [`RequestBuilder::send_streaming`]. The response body is deframed with a
/// [`GrpcFramer`].
///
/// ## Headers (caller order, emitted by HPACK in insertion order)
/// - `content-type: application/grpc+proto`
/// - `te: trailers` (also the signal the transport uses to surface trailers, so a
///   gRPC request automatically gets trailer delivery)
/// - `grpc-encoding: gzip`, only when `encoding` is [`GrpcEncoding::Gzip`]
///
/// Pseudo-headers reuse the active fingerprint profile's order, which is correct
/// for any `POST`; this constructor does not alter pseudo ordering or default
/// header synthesis. The caller-set `content-type` is never clobbered: the builder
/// only synthesizes a content-type from `.json()` / `.form()`, neither of which a
/// gRPC body uses.
///
/// ## Fingerprint scope
/// This layers gRPC *semantics* onto the client's existing (e.g. Chrome/Firefox)
/// H2 fingerprint. It does not impersonate a grpc-go/grpc-java runtime on the
/// wire; that is a separate, larger effort and out of scope.
///
/// ## Example
/// ```no_run
/// use specter::Client;
/// use specter::grpc::{encode_message, grpc_request, GrpcEncoding, GrpcFramer};
///
/// # async fn run() -> specter::Result<()> {
/// let client = Client::new()?;
/// let framed = encode_message(b"\x0a\x05world", false, GrpcEncoding::Identity)?;
/// let mut response = grpc_request(
///     &client,
///     "https://host/helloworld.Greeter/SayHello",
///     GrpcEncoding::Identity,
/// )
/// .body(framed)
/// .send_streaming()
/// .await?;
///
/// let mut framer = GrpcFramer::new(GrpcEncoding::Identity);
/// while let Some(frame) = response.body_mut().frame().await {
///     framer.push(frame?);
///     while let Some(_message) = framer.next_message()? {
///         // decode protobuf message bytes here
///     }
/// }
/// let _trailers = response.trailers().await?; // carries grpc-status / grpc-message
/// # Ok(())
/// # }
/// ```
pub fn grpc_request<'a>(
    client: &'a Client,
    url: impl IntoUrl,
    encoding: GrpcEncoding,
) -> RequestBuilder<'a> {
    let mut builder = client
        .post(url)
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers");
    if encoding == GrpcEncoding::Gzip {
        builder = builder.header("grpc-encoding", "gzip");
    }
    builder
}
