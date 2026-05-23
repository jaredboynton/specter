//! HTTP/2 connection handle - non-blocking interface for sending requests.
//!
//! The handle sends commands to a driver task and receives responses via channels.
//! Multiple handles can share the same driver, enabling true multiplexing.

use bytes::Bytes;
use http::{Method, Uri};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::WriteHalf;
use tokio::sync::{mpsc, oneshot};

use crate::error::{Error, Result};
use crate::headers::Headers;
use crate::response::Response;
use crate::transport::connector::MaybeHttpsStream;
use crate::transport::h2::driver::{DriverCommand, InlineRegistration, StreamingHeadersResult};
use crate::transport::h2::tunnel::H2Tunnel;
use crate::transport::h2::write_half::H2WriteHalf;

/// Shared write/registration primer used by the inline streaming fast path.
///
/// `H2PooledConnection` builds one of these per pooled connection and shares
/// it with both the H2 driver and the H2 handle. The inline caller acquires
/// the write half via `Arc::clone`, writes HEADERS atomically alongside the
/// driver, and notifies the driver of the new stream via `register_tx`.
pub(crate) struct H2InlineState {
    pub(crate) write_half: Arc<H2WriteHalf<WriteHalf<MaybeHttpsStream>>>,
    pub(crate) peer_max_frame_size: Arc<AtomicU32>,
    pub(crate) initial_window_size: u32,
    pub(crate) register_tx: mpsc::UnboundedSender<InlineRegistration>,
    /// Counter used to enforce sequential eligibility. Incremented when an
    /// inline stream is in flight; decremented by the driver when the stream
    /// completes or is cancelled.
    pub(crate) inline_active: Arc<AtomicUsize>,
    /// Disabled while any RFC 8441 tunnel or pending body is in flight; the
    /// driver toggles this flag.
    pub(crate) inline_eligible: Arc<AtomicBool>,
}

/// HTTP/2 connection handle for sending requests
#[derive(Clone)]
pub struct H2Handle {
    /// Channel for sending commands to the driver
    command_tx: mpsc::Sender<DriverCommand>,
    /// Shared flag set when GOAWAY is received
    goaway_received: Arc<AtomicBool>,
    /// Optional inline streaming primer; absent in raw test contexts where
    /// no shared write half exists.
    inline: Option<Arc<H2InlineState>>,
}

impl H2Handle {
    /// Create a new handle with a command channel to the driver
    pub fn new(command_tx: mpsc::Sender<DriverCommand>, goaway_received: Arc<AtomicBool>) -> Self {
        Self {
            command_tx,
            goaway_received,
            inline: None,
        }
    }

    pub(crate) fn with_inline(
        command_tx: mpsc::Sender<DriverCommand>,
        goaway_received: Arc<AtomicBool>,
        inline: Arc<H2InlineState>,
    ) -> Self {
        Self {
            command_tx,
            goaway_received,
            inline: Some(inline),
        }
    }

    /// Check if the driver is still running and hasn't received GOAWAY
    pub fn is_alive(&self) -> bool {
        !self.command_tx.is_closed() && !self.goaway_received.load(Ordering::Relaxed)
    }

    /// Send an HTTP/2 request and receive the response.
    /// This is non-blocking - it sends the request to the driver and awaits the response channel.
    /// The driver allocates stream IDs internally.
    pub async fn send_request(
        &self,
        method: Method,
        uri: &Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        let (response_tx, response_rx) = oneshot::channel();

        let command = DriverCommand::SendRequest {
            method,
            uri: uri.clone(),
            headers,
            body,
            response_tx,
        };

        self.command_tx
            .send(command)
            .await
            .map_err(|_| Error::HttpProtocol("Driver channel closed".into()))?;

        let stream_response = response_rx
            .await
            .map_err(|_| Error::HttpProtocol("Response channel closed".into()))??;

        Ok(Response::new(
            stream_response.status,
            Headers::from(stream_response.headers),
            stream_response.body,
            "HTTP/2".to_string(),
        ))
    }

    /// Send an HTTP/2 streaming request, preferring the inline shared-writer
    /// fast path for sequential body-less requests when eligible.
    /// Falls back to the driver command path otherwise.
    pub async fn send_streaming_request(
        &self,
        method: Method,
        uri: &Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<(Response, mpsc::Receiver<Result<Bytes>>)> {
        if let Some(result) = self
            .try_send_streaming_inline(&method, uri, &headers, &body)
            .await
        {
            return result;
        }
        self.send_streaming_request_command_path(method, uri, headers, body)
            .await
    }

    async fn send_streaming_request_command_path(
        &self,
        method: Method,
        uri: &Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<(Response, mpsc::Receiver<Result<Bytes>>)> {
        let (headers_tx, headers_rx) = oneshot::channel();
        let (body_tx, body_rx) = mpsc::channel(32);

        let command = DriverCommand::SendStreamingRequest {
            method,
            uri: uri.clone(),
            headers,
            body,
            body_tx,
            headers_tx,
        };

        self.command_tx
            .send(command)
            .await
            .map_err(|_| Error::HttpProtocol("Driver channel closed".into()))?;

        let (status, regular_headers) = headers_rx
            .await
            .map_err(|_| Error::HttpProtocol("Headers channel closed".into()))??;

        Ok((
            Response::new(
                status,
                Headers::from(regular_headers),
                Bytes::new(),
                "HTTP/2".to_string(),
            ),
            body_rx,
        ))
    }

    /// Attempt the inline shared-writer streaming fast path. Returns
    /// `Some(result)` when the path was attempted (either successfully or
    /// with a transport error), or `None` when the request is ineligible
    /// and the caller must use the command path fallback.
    async fn try_send_streaming_inline(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &[(String, String)],
        body: &Option<Bytes>,
    ) -> Option<Result<(Response, mpsc::Receiver<Result<Bytes>>)>> {
        let inline = self.inline.as_ref()?;
        if !self.is_alive() {
            return None;
        }
        if body.as_ref().is_some_and(|b| !b.is_empty()) {
            return None;
        }
        if !inline.inline_eligible.load(Ordering::Relaxed) {
            return None;
        }

        if inline
            .inline_active
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }

        let (headers_tx, headers_rx) = oneshot::channel::<StreamingHeadersResult>();
        let (body_tx, body_rx) = mpsc::channel::<Result<Bytes>>(32);

        let max_frame_size = inline.peer_max_frame_size.load(Ordering::Relaxed) as usize;
        let stream_id = match inline
            .write_half
            .write_request_headers(method, uri, headers, true, max_frame_size)
            .await
        {
            Ok(id) => id,
            Err(error) => {
                inline.inline_active.fetch_sub(1, Ordering::AcqRel);
                return Some(Err(error));
            }
        };

        let registration = InlineRegistration {
            stream_id,
            headers_tx,
            body_tx,
            recv_window: inline.initial_window_size as i32,
        };

        if inline.register_tx.send(registration).is_err() {
            inline.inline_active.fetch_sub(1, Ordering::AcqRel);
            return Some(Err(Error::HttpProtocol("Driver channel closed".into())));
        }

        let result = match headers_rx.await {
            Ok(Ok((status, regular_headers))) => Ok((
                Response::new(
                    status,
                    Headers::from(regular_headers),
                    Bytes::new(),
                    "HTTP/2".to_string(),
                ),
                body_rx,
            )),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::HttpProtocol("Headers channel closed".into())),
        };

        Some(result)
    }

    /// Open an RFC 8441 WebSocket tunnel through the background H2 driver.
    pub async fn open_websocket_tunnel(
        &self,
        uri: Uri,
        headers: Vec<(String, String)>,
    ) -> Result<H2Tunnel> {
        let (response_tx, response_rx) = oneshot::channel();

        self.command_tx
            .send(DriverCommand::OpenWebSocketTunnel {
                uri,
                headers,
                response_tx,
            })
            .await
            .map_err(|_| Error::HttpProtocol("Driver channel closed".into()))?;

        response_rx
            .await
            .map_err(|_| Error::HttpProtocol("Tunnel response channel closed".into()))?
    }
}
