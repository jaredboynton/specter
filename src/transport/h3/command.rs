use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use tokio::sync::oneshot;

use crate::error::Result;
use crate::headers::Headers;
use crate::request::RequestBody;
use crate::transport::h3::body::H3BodyShared;
use crate::transport::h3::H3Tunnel;

pub type StreamingHeadersResult = Result<(u16, Headers)>;

#[derive(Debug)]
pub struct NativeH3PhaseTrace {
    base: Instant,
    handle_command_ready_ns: AtomicU64,
    command_enqueued_ns: AtomicU64,
    headers_wait_start_ns: AtomicU64,
    caller_headers_ready_ns: AtomicU64,
    driver_command_received_ns: AtomicU64,
    request_packet_built_ns: AtomicU64,
    stream_registered_ns: AtomicU64,
    packet_send_done_ns: AtomicU64,
    udp_recv_return_ns: AtomicU64,
    h3_events_decoded_ns: AtomicU64,
    streaming_headers_event_ns: AtomicU64,
    headers_oneshot_sent_ns: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NativeH3PhaseTraceSnapshot {
    pub handle_command_ready_ns: Option<u64>,
    pub command_enqueued_ns: Option<u64>,
    pub headers_wait_start_ns: Option<u64>,
    pub caller_headers_ready_ns: Option<u64>,
    pub driver_command_received_ns: Option<u64>,
    pub request_packet_built_ns: Option<u64>,
    pub stream_registered_ns: Option<u64>,
    pub packet_send_done_ns: Option<u64>,
    pub udp_recv_return_ns: Option<u64>,
    pub h3_events_decoded_ns: Option<u64>,
    pub streaming_headers_event_ns: Option<u64>,
    pub headers_oneshot_sent_ns: Option<u64>,
}

impl NativeH3PhaseTrace {
    pub fn new(base: Instant) -> Self {
        Self {
            base,
            handle_command_ready_ns: AtomicU64::new(0),
            command_enqueued_ns: AtomicU64::new(0),
            headers_wait_start_ns: AtomicU64::new(0),
            caller_headers_ready_ns: AtomicU64::new(0),
            driver_command_received_ns: AtomicU64::new(0),
            request_packet_built_ns: AtomicU64::new(0),
            stream_registered_ns: AtomicU64::new(0),
            packet_send_done_ns: AtomicU64::new(0),
            udp_recv_return_ns: AtomicU64::new(0),
            h3_events_decoded_ns: AtomicU64::new(0),
            streaming_headers_event_ns: AtomicU64::new(0),
            headers_oneshot_sent_ns: AtomicU64::new(0),
        }
    }

    fn elapsed_ns(&self) -> u64 {
        let nanos = self.base.elapsed().as_nanos();
        (nanos.min(u128::from(u64::MAX)) as u64).max(1)
    }

    fn stamp(field: &AtomicU64, value: u64) {
        let _ = field.compare_exchange(0, value, Ordering::Relaxed, Ordering::Relaxed);
    }

    fn read(field: &AtomicU64) -> Option<u64> {
        match field.load(Ordering::Relaxed) {
            0 => None,
            value => Some(value),
        }
    }

    pub(crate) fn stamp_handle_command_ready(&self) {
        Self::stamp(&self.handle_command_ready_ns, self.elapsed_ns());
    }

    pub(crate) fn stamp_command_enqueued(&self) {
        Self::stamp(&self.command_enqueued_ns, self.elapsed_ns());
    }

    pub(crate) fn stamp_headers_wait_start(&self) {
        Self::stamp(&self.headers_wait_start_ns, self.elapsed_ns());
    }

    pub(crate) fn stamp_caller_headers_ready(&self) {
        Self::stamp(&self.caller_headers_ready_ns, self.elapsed_ns());
    }

    pub(crate) fn stamp_driver_command_received(&self) {
        Self::stamp(&self.driver_command_received_ns, self.elapsed_ns());
    }

    pub(crate) fn stamp_request_packet_built(&self) {
        Self::stamp(&self.request_packet_built_ns, self.elapsed_ns());
    }

    pub(crate) fn stamp_stream_registered(&self) {
        Self::stamp(&self.stream_registered_ns, self.elapsed_ns());
    }

    pub(crate) fn stamp_packet_send_done(&self) {
        Self::stamp(&self.packet_send_done_ns, self.elapsed_ns());
    }

    pub(crate) fn stamp_udp_recv_return(&self) {
        Self::stamp(&self.udp_recv_return_ns, self.elapsed_ns());
    }

    pub(crate) fn stamp_h3_events_decoded(&self) {
        Self::stamp(&self.h3_events_decoded_ns, self.elapsed_ns());
    }

    pub(crate) fn stamp_streaming_headers_event(&self) {
        Self::stamp(&self.streaming_headers_event_ns, self.elapsed_ns());
    }

    pub(crate) fn stamp_headers_oneshot_sent(&self) {
        Self::stamp(&self.headers_oneshot_sent_ns, self.elapsed_ns());
    }

    pub fn snapshot(&self) -> NativeH3PhaseTraceSnapshot {
        NativeH3PhaseTraceSnapshot {
            handle_command_ready_ns: Self::read(&self.handle_command_ready_ns),
            command_enqueued_ns: Self::read(&self.command_enqueued_ns),
            headers_wait_start_ns: Self::read(&self.headers_wait_start_ns),
            caller_headers_ready_ns: Self::read(&self.caller_headers_ready_ns),
            driver_command_received_ns: Self::read(&self.driver_command_received_ns),
            request_packet_built_ns: Self::read(&self.request_packet_built_ns),
            stream_registered_ns: Self::read(&self.stream_registered_ns),
            packet_send_done_ns: Self::read(&self.packet_send_done_ns),
            udp_recv_return_ns: Self::read(&self.udp_recv_return_ns),
            h3_events_decoded_ns: Self::read(&self.h3_events_decoded_ns),
            streaming_headers_event_ns: Self::read(&self.streaming_headers_event_ns),
            headers_oneshot_sent_ns: Self::read(&self.headers_oneshot_sent_ns),
        }
    }
}

/// Command sent from handle to driver.
///
/// Tunnel-data DATA frames do not flow through this control channel;
/// they take a dedicated mpsc owned by the driver so a freshly issued
/// streaming-request or tunnel-open is never queued behind a burst of
/// in-flight RFC 9220 tunnel writes.
#[derive(Debug)]
pub enum DriverCommand {
    /// Send a request and get response via oneshot.
    SendRequest {
        method: http::Method,
        uri: http::Uri,
        headers: Headers,
        body: Option<Bytes>,
        response_tx: oneshot::Sender<Result<StreamResponse>>,
    },
    /// Send a request and return headers as soon as they arrive, with DATA routed
    /// incrementally through the body channel.
    SendStreamingRequest {
        method: http::Method,
        uri: http::Uri,
        headers: Headers,
        body: RequestBody,
        headers_tx: oneshot::Sender<StreamingHeadersResult>,
        body_shared: Arc<H3BodyShared>,
        phase_trace: Option<Arc<NativeH3PhaseTrace>>,
    },
    /// Open an RFC 9220 WebSocket-over-HTTP/3 tunnel.
    OpenWebSocketTunnel {
        uri: http::Uri,
        headers: Vec<(String, String)>,
        response_tx: oneshot::Sender<Result<H3Tunnel>>,
    },
}

#[derive(Debug)]
pub struct StreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}
