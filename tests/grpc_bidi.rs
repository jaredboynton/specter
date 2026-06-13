//! Full-duplex gRPC verification (gRPC Phase 4).
//!
//! Two integration tests against a local mock H2 server bound to `127.0.0.1:0`:
//!
//! 1. **Sanity floor** (`grpc_unary_with_framed_body_round_trip`): a unary-style
//!    gRPC exchange that carries a *real framed request body*. The client frames
//!    one message with [`encode_message`], sends it via [`grpc_request`] +
//!    [`RequestBuilder::body`], the fixture reads the request DATA, replies with
//!    200 + a framed response message + trailing `grpc-status: 0`. The client
//!    deframes with [`GrpcFramer`] and reads `trailers()`. This resolves the
//!    Phase 3 deferral: the earlier "Headers channel closed" was a fixture
//!    artifact (a handler that dropped the connection mid-upload), not a client
//!    defect. A real request body flows end-to-end through the gRPC surface.
//!
//! 2. **Bidi under a constrained window** (`grpc_bidi_interleaves_under_small_window`):
//!    the spec's core. Drives the command path (`handle.rs:179` - a non-empty
//!    streaming body cannot use the inline path, which requires `body_is_empty`)
//!    with a **small `h2_streaming_body_buffer_slots`** so the in-flight buffer
//!    window is constrained. The request body is a caller-paced mpsc-backed
//!    `Stream`; the server advertises a small per-stream send window (4096) and
//!    grants request-stream `WINDOW_UPDATE` in increments, so a 12 KiB request
//!    message cannot be flushed in one shot - it parks mid-message awaiting grants
//!    while inbound response DATA must keep flowing.
//!
//!    The interleaving proof is structural, not a byte-counting witness: one client
//!    task drives both directions with a strict causal dependency - it stages
//!    outbound round *k+1* only after deframing the inbound echo for round *k*. A
//!    driver that serialized the two halves (flush the entire request body, then
//!    drain inbound, or the reverse) can never advance past round 1 and would
//!    deadlock into the timeout: it cannot deliver echo 1 without reading inbound,
//!    and cannot obtain message 2 without first delivering echo 1. Completing all
//!    rounds is therefore reachable only if the driver genuinely interleaves flush
//!    and drain on the one stream. Finally the request stream closes (drop the
//!    sender) and the client reads `grpc-status: 0` trailers.
//!
//! No fixed sleeps; no fixed ports; per-test mock server. The server handler is a
//! single task that interleaves reads and writes in one loop (the connection
//! stream is behind a `Mutex`, so a parked `read_frame` must never hold the lock
//! while the test expects a write).
#![cfg(feature = "grpc")]

use bytes::Bytes;
use futures_core::Stream;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use warpsock::grpc::{encode_message, grpc_request, GrpcEncoding, GrpcFramer};
use warpsock::transport::h2::hpack_impl::Encoder;
use warpsock::{Client, Error};

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};
use helpers::tls::generate_cert_bundle;

/// Build an ALPN-h2 TLS acceptor and a client trusting its CA. `slots` sets the
/// H2 streaming-body buffer capacity (`H2BodyShared` capacity) so the bidi test
/// can constrain the in-flight window.
fn h2_tls_setup(slots: usize) -> (boring::ssl::SslAcceptor, Client) {
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = builder.build();
    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .h2_streaming_body_buffer_slots(slots)
        .build()
        .unwrap();
    (acceptor, client)
}

/// A request-body `Stream` backed by an mpsc channel of pre-framed gRPC messages.
/// The test pushes framed messages into the sender; the driver pulls from this
/// at its own pace (parking when the slot/window window is full). Closing the
/// sender ends the request stream (END_STREAM).
struct ChannelBody {
    rx: mpsc::Receiver<Bytes>,
}

impl Stream for ChannelBody {
    type Item = std::result::Result<Bytes, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => Poll::Ready(Some(Ok(chunk))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Read frames until a DATA frame arrives on `stream_id`, accumulating its bytes.
/// Returns the DATA payload and whether END_STREAM was set. Skips non-DATA frames
/// (the client may interleave WINDOW_UPDATE / SETTINGS). Records HEADERS stream id
/// into `stream_id` on first sight.
async fn read_next_data(
    conn: &MockH2Connection,
    stream_id: &mut u32,
) -> std::io::Result<(Bytes, bool)> {
    loop {
        let (_, frame_type, flags, sid, payload) = conn.read_frame().await?;
        match frame_type {
            0x01 => *stream_id = sid,
            0x00 => return Ok((payload, flags & 0x01 != 0)),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Test 1: sanity floor - gRPC unary exchange with a real framed request body.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn grpc_unary_with_framed_body_round_trip() {
    let (acceptor, client) = h2_tls_setup(8);
    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let request_payload = b"\x0a\x05world".to_vec();
    let response_payload = b"reply-message".to_vec();
    let request_payload_server = request_payload.clone();
    let response_payload_server = response_payload.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let expected_request = request_payload_server.clone();
        let response_body = response_payload_server.clone();
        async move {
            conn.read_preface().await.unwrap();
            conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                .await
                .unwrap();
            conn.send_settings_ack().await.unwrap();

            let mut stream_id = 0u32;
            // Read the request HEADERS (no END_STREAM, body follows) then the
            // request DATA carrying the framed message.
            let mut received = Vec::new();
            let mut ended = false;
            while !ended {
                let (payload, end) = read_next_data(&conn, &mut stream_id).await.unwrap();
                if !payload.is_empty() {
                    conn.send_window_update(0, payload.len() as u32)
                        .await
                        .unwrap();
                    conn.send_window_update(stream_id, payload.len() as u32)
                        .await
                        .unwrap();
                    received.extend_from_slice(&payload);
                }
                ended = end;
            }

            // The received request DATA must be exactly one framed gRPC message.
            let mut framer = GrpcFramer::new(GrpcEncoding::Identity);
            framer.push(Bytes::from(received));
            let msg = framer
                .next_message()
                .expect("decode request")
                .expect("one framed request message");
            assert_eq!(&msg[..], &expected_request[..]);
            assert!(framer.next_message().expect("drain").is_none());

            // Respond: 200 headers, one framed response message, trailers.
            let mut encoder = Encoder::new();
            let response_headers = encoder.encode(&[
                (b":status".as_slice(), b"200".as_slice()),
                (
                    b"content-type".as_slice(),
                    b"application/grpc+proto".as_slice(),
                ),
            ]);
            conn.send_headers(stream_id, &response_headers, false, true)
                .await
                .unwrap();
            let framed_response =
                encode_message(&response_body, false, GrpcEncoding::Identity).unwrap();
            conn.send_data(stream_id, &framed_response, false)
                .await
                .unwrap();
            let trailers = encoder.encode(&[(b"grpc-status".as_slice(), b"0".as_slice())]);
            conn.send_headers(stream_id, &trailers, true, true)
                .await
                .unwrap();
        }
    });

    let req_url = format!("{}/pkg.Svc/Unary", url);
    let framed_request = encode_message(&request_payload, false, GrpcEncoding::Identity).unwrap();

    let mut response = timeout(
        Duration::from_secs(5),
        grpc_request(&client, &req_url, GrpcEncoding::Identity)
            .body(framed_request)
            .send_streaming(),
    )
    .await
    .expect("request future must not time out")
    .expect("gRPC request with framed body must complete");

    assert_eq!(response.status().as_u16(), 200);

    // Deframe the response body.
    let mut framer = GrpcFramer::new(GrpcEncoding::Identity);
    let mut messages: Vec<Bytes> = Vec::new();
    while let Some(frame) = response.body_mut().frame().await {
        let data = frame.expect("response body frame").into_data().unwrap();
        framer.push(data);
        while let Some(m) = framer.next_message().expect("decode response") {
            messages.push(m);
        }
    }
    assert_eq!(messages.len(), 1, "exactly one response message");
    assert_eq!(&messages[0][..], &response_payload[..]);

    let trailers = timeout(Duration::from_secs(5), response.trailers())
        .await
        .expect("trailers() must resolve")
        .expect("trailers() must not error on a clean trailer frame")
        .expect("a real trailer frame yields Some(headers)");
    assert_eq!(trailers.get("grpc-status"), Some("0"));
}

// ---------------------------------------------------------------------------
// Test 2: full-duplex bidi under a constrained flow-control / buffer window.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn grpc_bidi_interleaves_under_small_window() {
    // 1-slot in-flight buffer: only one request-body chunk may be queued at a
    // time, so the driver must flush it (outbound) before accepting the next,
    // while concurrently draining inbound response DATA. This is the constrained
    // window the spec requires (handle.rs:197/205 feed H2BodyShared capacity).
    let (acceptor, client) = h2_tls_setup(1);
    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    const ROUNDS: usize = 6;
    // Each request message payload is large relative to the advertised per-stream
    // send window (4096 below) so flushing one message needs several
    // WINDOW_UPDATE grants - the client's outbound stream window binds and parks.
    // It is kept under MAX_FRAME_SIZE (16384) so the framed message (payload + 5)
    // fits one DATA frame in each direction without a FRAME_SIZE_ERROR.
    const MSG_LEN: usize = 12 * 1024;

    // Number of echoed response DATA frames the server emitted. The interleaving
    // proof lives in the client's strict round dependency (see the drive loop
    // below); this counter is only a 1:1 sanity check that the server echoed every
    // round it received.
    let responses_emitted = Arc::new(AtomicUsize::new(0));
    let responses_emitted_server = responses_emitted.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let responses_emitted = responses_emitted_server.clone();
        async move {
            conn.read_preface().await.unwrap();
            // Advertise a SMALL per-stream send window (SETTINGS_INITIAL_WINDOW_SIZE
            // = 4096) so the client cannot blast a whole 12 KiB message at once;
            // it must wait for incremental WINDOW_UPDATE grants, which the server
            // emits between echoed response DATA frames. That is what makes the
            // outbound half genuinely park while the inbound half progresses.
            conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 4096)])
                .await
                .unwrap();
            conn.send_settings_ack().await.unwrap();

            let mut encoder = Encoder::new();
            let mut stream_id = 0u32;
            let mut headers_sent = false;
            // Reassemble framed request messages across DATA frames.
            let mut framer = GrpcFramer::new(GrpcEncoding::Identity);

            loop {
                // Generous per-read budget: under the constrained window the
                // client can legitimately go quiet for a while between writes, so
                // a 1s read (the helper default) would close the connection
                // mid-exchange and masquerade as a driver stall.
                let Ok((_, frame_type, flags, sid, payload)) =
                    conn.read_frame_with_timeout(Duration::from_secs(10)).await
                else {
                    break;
                };
                match frame_type {
                    0x01 => {
                        stream_id = sid;
                        // Send 200 response headers immediately on receiving the
                        // request HEADERS - a gRPC server emits response headers
                        // before the first message, and this unblocks the client's
                        // `send_streaming()` (status>=200) independent of request
                        // body completion (driver.rs:1750), which is exactly the
                        // early-header behavior the duplex path relies on.
                        if !headers_sent {
                            let response_headers = encoder.encode(&[
                                (b":status".as_slice(), b"200".as_slice()),
                                (
                                    b"content-type".as_slice(),
                                    b"application/grpc+proto".as_slice(),
                                ),
                            ]);
                            conn.send_headers(stream_id, &response_headers, false, true)
                                .await
                                .unwrap();
                            headers_sent = true;
                        }
                    }
                    0x00 => {
                        let end = flags & 0x01 != 0;
                        if !payload.is_empty() {
                            // Grant window in increments so the client's stream
                            // send window keeps re-opening but never gets far
                            // ahead - sustained parking under load.
                            conn.send_window_update(0, payload.len() as u32)
                                .await
                                .unwrap();
                            conn.send_window_update(stream_id, payload.len() as u32)
                                .await
                                .unwrap();
                            framer.push(payload.clone());
                        }

                        // Echo every fully-received request message back as a
                        // response DATA frame.
                        while let Some(msg) = framer.next_message().expect("decode request") {
                            let framed =
                                encode_message(&msg, false, GrpcEncoding::Identity).unwrap();
                            conn.send_data(stream_id, &framed, false).await.unwrap();
                            responses_emitted.fetch_add(1, Ordering::SeqCst);
                        }

                        if end {
                            // Request stream closed: send trailers and finish.
                            let trailers =
                                encoder.encode(&[(b"grpc-status".as_slice(), b"0".as_slice())]);
                            conn.send_headers(stream_id, &trailers, true, true)
                                .await
                                .unwrap();
                            break;
                        }
                    }
                    0x03 => break,
                    _ => {}
                }
            }
        }
    });

    let req_url = format!("{}/pkg.Svc/Bidi", url);
    // Capacity 1: the channel holds at most the single message the loop has staged
    // for the next round. The loop never runs ahead - it stages round k+1 only
    // after deframing the echo for round k - so this is a hand-off, never a buffer
    // the driver can drain to completion up front.
    let (tx, rx) = mpsc::channel::<Bytes>(1);
    let body = ChannelBody { rx };

    let framed_msg =
        || encode_message(&vec![b'x'; MSG_LEN], false, GrpcEncoding::Identity).unwrap();

    // Stage round 1 before opening the stream so the request has DATA to flush
    // while the client is still awaiting response headers - the duplex ordering -
    // and it avoids a "server waits for DATA, client waits for headers" stall. tx
    // stays owned by this task; every later round is gated on its inbound echo.
    tx.send(framed_msg())
        .await
        .expect("staging round 1 must not fail");
    // Hold the sender in an Option so the final round can `take()` and drop it
    // (-> END_STREAM) without tripping a move-across-loop-iterations error.
    let mut tx = Some(tx);

    let mut response = timeout(
        Duration::from_secs(5),
        grpc_request(&client, &req_url, GrpcEncoding::Identity)
            .body_stream(body)
            .send_streaming(),
    )
    .await
    .expect("send_streaming future must not time out")
    .expect("bidi gRPC request must open");
    assert_eq!(response.status().as_u16(), 200);

    // One task drives BOTH directions with a strict causal dependency: outbound
    // round k+1 is staged only AFTER inbound echo k is deframed. This is what makes
    // completion *prove* interleaving rather than buffering. A driver that
    // serialized the two halves - flush the whole request body, then drain inbound
    // (or the reverse) - can never advance past round 1: it cannot deliver echo 1
    // without reading inbound, and it cannot obtain message 2 without first
    // delivering echo 1. It would block forever and trip the timeout below.
    // Reaching ROUNDS is only possible if the driver genuinely interleaves flush
    // and drain on the one stream. Under slots=1 plus a 4096-byte send window vs a
    // 12 KiB message, each outbound round also parks mid-message awaiting
    // WINDOW_UPDATE while inbound must keep flowing - so it is real contention, not
    // a buffered free ride.
    let mut framer = GrpcFramer::new(GrpcEncoding::Identity);
    let mut received_rounds = 0usize;
    let drive = async {
        while received_rounds < ROUNDS {
            let frame = response
                .body_mut()
                .frame()
                .await
                .expect("body must yield a frame before end")
                .expect("response body frame must not error");
            framer.push(frame.into_data().unwrap());
            while let Some(msg) = framer.next_message().expect("decode response") {
                assert_eq!(msg.len(), MSG_LEN, "echoed message length must match");
                assert!(msg.iter().all(|&b| b == b'x'), "echoed payload must match");
                received_rounds += 1;
                // Gate the NEXT outbound round on having received THIS echo. After
                // the final echo, drop the sender -> ChannelBody yields None ->
                // END_STREAM on the request stream.
                if received_rounds < ROUNDS {
                    tx.as_ref()
                        .expect("sender live until final round")
                        .send(framed_msg())
                        .await
                        .expect("staging next round must not fail");
                } else {
                    tx = None;
                    break;
                }
            }
        }
    };
    timeout(Duration::from_secs(15), drive)
        .await
        .expect("bidi exchange must interleave both directions, not serialize one then the other");

    assert_eq!(
        received_rounds, ROUNDS,
        "client must deframe every echoed round"
    );
    assert_eq!(
        responses_emitted.load(Ordering::SeqCst),
        ROUNDS,
        "server must echo every round"
    );

    // Finally, the trailers (grpc-status: 0) after the request stream closed.
    let trailers = timeout(Duration::from_secs(5), response.trailers())
        .await
        .expect("trailers() must resolve after request stream close")
        .expect("trailers() must not error on clean trailer frame")
        .expect("a real trailer frame yields Some(headers)");
    assert_eq!(trailers.get("grpc-status"), Some("0"));
}
