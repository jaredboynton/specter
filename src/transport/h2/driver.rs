//! HTTP/2 connection driver - background task that reads frames and routes them to streams.
//!
//! The driver owns the raw H2Connection and continuously reads frames from the socket,
//! routing them to the appropriate stream channels. This allows multiple requests
//! to be multiplexed without blocking each other.

use bytes::{Bytes, BytesMut};
use http::{Method, Uri};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing;

pub type StreamingHeadersResult = Result<(u16, Vec<(String, String)>)>;

use crate::error::{Error, Result};
use crate::transport::h2::connection::{
    ControlAction, H2Connection as RawH2Connection, StreamResponse,
};
use crate::transport::h2::frame::{flags, ErrorCode, FrameHeader, FrameType};

/// Command sent from handle to driver
#[derive(Debug)]
pub enum DriverCommand {
    /// Send a request and get response via oneshot
    /// Driver allocates stream_id
    SendRequest {
        method: http::Method,
        uri: http::Uri,
        headers: Vec<(String, String)>,
        body: Option<bytes::Bytes>,
        response_tx: oneshot::Sender<Result<StreamResponse>>,
    },
    /// Send a request with a streaming body
    SendStreamingRequest {
        method: Method,
        uri: Uri,
        headers: Vec<(String, String)>,
        body_tx: mpsc::Sender<Result<Bytes>>,
        headers_tx: oneshot::Sender<StreamingHeadersResult>,
    },
}

/// Per-stream state tracked by driver
struct DriverStreamState {
    /// Oneshot sender for response completion
    response_tx: Option<oneshot::Sender<Result<StreamResponse>>>,
    /// Accumulated response status
    status: Option<u16>,
    /// Accumulated response headers
    headers: Vec<(String, String)>,
    /// Accumulated response body
    body: BytesMut,
    /// Pending request body to be sent (flow control buffer)
    pending_body: Bytes,
    /// Offset of pending body already sent
    body_offset: usize,
}

impl DriverStreamState {
    fn new(response_tx: oneshot::Sender<Result<StreamResponse>>, pending_body: Bytes) -> Self {
        Self {
            response_tx: Some(response_tx),
            status: None,
            headers: Vec::new(),
            body: BytesMut::new(),
            pending_body,
            body_offset: 0,
        }
    }
}

/// HTTP/2 connection driver that runs in a background task
pub struct H2Driver<S> {
    /// Channel for receiving commands from handles
    command_rx: mpsc::Receiver<DriverCommand>,
    /// Raw H2 connection (owned by driver)
    connection: RawH2Connection<S>,
    /// Per-stream state for routing responses
    streams: HashMap<u32, DriverStreamState>,
    /// Queue for pending requests when max streams reached
    pending_requests: std::collections::VecDeque<DriverCommand>,
}

impl<S> H2Driver<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    /// Create a new driver from an established connection
    pub fn new(connection: RawH2Connection<S>, command_rx: mpsc::Receiver<DriverCommand>) -> Self {
        Self {
            command_rx,
            connection,
            streams: HashMap::new(),
            pending_requests: std::collections::VecDeque::new(),
        }
    }

    /// Run the driver loop - processes commands and reads frames
    pub async fn drive(mut self) -> Result<()> {
        loop {
            // Processing pending requests if slots available
            self.process_pending_requests().await?;

            // Try to flush any pending data (flow control)
            self.flush_pending_data().await?;

            tokio::select! {
                // Handle incoming commands (send requests)
                command = self.command_rx.recv() => {
                    match command {
                        Some(cmd) => {
                             match cmd {
                                DriverCommand::SendRequest { .. } => {
                                    self.handle_send_request(cmd).await?;
                                }
                                DriverCommand::SendStreamingRequest { .. } => {
                                    tracing::warn!("Streaming requests not yet implemented in driver");
                                }
                             }
                        }
                        None => {
                            // Channel closed - driver should shutdown
                            break;
                        }
                    }
                }

                // Handle incoming frames
                read_res = self.connection.read_next_frame() => {
                    match read_res {
                        Ok((header, payload)) => {
                            if let Err(e) = self.handle_frame(header, payload).await {
                                tracing::error!("H2Driver frame error: {:?}", e);
                                // Protocol errors are fatal and require connection termination.
                                // The connection state may be inconsistent after this error.
                                return Err(e);
                            }
                        }
                        Err(e) => {
                             // Connection error
                            tracing::error!("H2Driver read error: {:?}", e);
                            return Err(e);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Handle SendRequest command
    async fn handle_send_request(&mut self, cmd: DriverCommand) -> Result<()> {
        let max_streams = self.connection.peer_settings().max_concurrent_streams;

        if self.streams.len() >= max_streams as usize {
            // Queue request
            self.pending_requests.push_back(cmd);
        } else {
            // Send immediately
            self.send_request_internal(cmd).await?;
        }
        Ok(())
    }

    /// Process pending requests if slots available
    async fn process_pending_requests(&mut self) -> Result<()> {
        let max_streams = self.connection.peer_settings().max_concurrent_streams;

        while self.streams.len() < max_streams as usize {
            if let Some(cmd) = self.pending_requests.pop_front() {
                self.send_request_internal(cmd).await?;
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Internal helper to send request
    async fn send_request_internal(&mut self, cmd: DriverCommand) -> Result<()> {
        if let DriverCommand::SendRequest {
            method,
            uri,
            headers,
            body,
            response_tx,
        } = cmd
        {
            // Construct request
            let mut req_builder = http::Request::builder().method(method).uri(uri);

            for (k, v) in headers {
                req_builder = req_builder.header(k, v);
            }

            // Body
            let body_bytes = body.unwrap_or_default();
            let has_body = !body_bytes.is_empty();

            let req = match req_builder.body(body_bytes.clone()) {
                Ok(r) => r,
                Err(e) => {
                    if response_tx
                        .send(Err(Error::HttpProtocol(format!("Invalid request: {}", e))))
                        .is_err()
                    {
                        tracing::debug!("Response channel closed while sending error");
                    }
                    return Ok(());
                }
            };

            // Send HEADERS frame (non-blocking write)
            // If body is present, end_stream=false (DATA frames will be sent separately)
            let end_stream = !has_body;

            match self.connection.send_headers(&req, end_stream).await {
                Ok(stream_id) => {
                    // Register stream state
                    self.streams
                        .insert(stream_id, DriverStreamState::new(response_tx, body_bytes));

                    // Trigger flush to try sending body immediately
                    self.flush_pending_data().await?;
                }
                Err(e) => {
                    // Notify error immediately
                    if response_tx.send(Err(e)).is_err() {
                        tracing::debug!("Response channel closed while sending error");
                    }
                }
            }
        }
        Ok(())
    }

    /// Iterate all active streams and try to send pending body data
    async fn flush_pending_data(&mut self) -> Result<()> {
        // Collect IDs to avoid borrow conflict
        let stream_ids: Vec<u32> = self.streams.keys().cloned().collect();

        for stream_id in stream_ids {
            // Keep sending chunks for this stream until blocked or done
            loop {
                // Check if we have data to send
                let (has_data, offset) = if let Some(stream) = self.streams.get(&stream_id) {
                    (
                        stream.body_offset < stream.pending_body.len(),
                        stream.body_offset,
                    )
                } else {
                    (false, 0)
                };

                if !has_data {
                    break;
                }

                // Prepare arguments for send_data
                // We clone the Bytes handle which is cheap
                let pending_body = {
                    let s = self.streams.get(&stream_id).unwrap();
                    s.pending_body.clone()
                };

                let remaining = &pending_body[offset..];
                let is_last_chunk = true;

                // send_data returns bytes sent. If 0, it means blocked.
                let sent = self
                    .connection
                    .send_data(stream_id, remaining, is_last_chunk)
                    .await?;

                if sent > 0 {
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        stream.body_offset += sent;
                    }
                    // Loop again to send next chunk
                } else {
                    // Blocked by flow control
                    break;
                }
            }
        }
        Ok(())
    }

    /// Handle a single frame
    async fn handle_frame(&mut self, header: FrameHeader, mut payload: Bytes) -> Result<()> {
        // 1. Check control frames that modify connection state
        match self
            .connection
            .handle_control_frame(&header, payload.clone())
            .await?
        {
            ControlAction::RstStream(sid, code) => {
                // Notify stream of reset
                if let Some(mut stream) = self.streams.remove(&sid) {
                    if let Some(tx) = stream.response_tx.take() {
                        if tx
                            .send(Err(Error::HttpProtocol(format!(
                                "Stream reset by peer: {:?}",
                                code
                            ))))
                            .is_err()
                        {
                            tracing::debug!("Response channel closed while notifying stream reset");
                        }
                    }
                }
                // Stream slot freed, try to process pending
                self.process_pending_requests().await?;
                return Ok(());
            }
            ControlAction::GoAway(last_sid) => {
                // Close all streams > last_sid
                let sids: Vec<u32> = self.streams.keys().cloned().collect();
                for sid in sids {
                    if sid > last_sid {
                        if let Some(mut stream) = self.streams.remove(&sid) {
                            if let Some(tx) = stream.response_tx.take() {
                                if tx
                                    .send(Err(Error::HttpProtocol("GOAWAY received".into())))
                                    .is_err()
                                {
                                    tracing::debug!(
                                        "Response channel closed while notifying GOAWAY"
                                    );
                                }
                            }
                        }
                    }
                }
                // Driver continues processing existing streams until they complete.
                // A future enhancement could implement immediate shutdown on GOAWAY.
                return Ok(());
            }
            ControlAction::RefusePush(_stream_id, promised_id) => {
                // Send RST_STREAM for the promised stream
                // RFC 9113 8.4: RST_STREAM with REFUSED_STREAM
                if let Err(e) = self
                    .connection
                    .send_rst_stream(promised_id, ErrorCode::RefusedStream)
                    .await
                {
                    tracing::warn!(
                        "Failed to send RST_STREAM for refused push promise: {:?}",
                        e
                    );
                }
            }
            ControlAction::None => {
                // Continue to specific processing
            }
        }

        // 2. Data / Headers routing
        match header.frame_type {
            FrameType::Headers => {
                let stream_id = header.stream_id;

                // Handle CONTINUATION frames if needed (END_HEADERS flag not set).
                // CONTINUATION frames are collected in the loop below; this branch handles
                // the initial HEADERS frame that starts a header block.
                if (header.flags & flags::END_HEADERS) == 0 {
                    // Loop to read CONTINUATION frames
                    // This inner loop blocks the driver select! loop, which is expected
                    // per RFC 9113 Section 6.2 (CONTINUATION frames must be processed sequentially).
                    let mut block = BytesMut::from(payload);
                    loop {
                        let (next_header, next_payload) = self.connection.read_next_frame().await?;
                        if next_header.frame_type != FrameType::Continuation {
                            return Err(Error::HttpProtocol("Expected CONTINUATION frame".into()));
                        }
                        if next_header.stream_id != stream_id {
                            return Err(Error::HttpProtocol(
                                "CONTINUATION frame stream ID mismatch".into(),
                            ));
                        }
                        block.extend_from_slice(&next_payload);
                        if (next_header.flags & flags::END_HEADERS) != 0 {
                            break;
                        }
                    }
                    payload = block.freeze();
                }

                let decoded = self.connection.decode_header_block(payload)?;

                // Parse pseudo-headers
                let mut status = 0u16;
                let mut regular_headers = Vec::new();

                for (name, value) in decoded {
                    if name == ":status" {
                        status = value.parse().unwrap_or(0);
                    } else if !name.starts_with(':') {
                        regular_headers.push((name, value));
                    }
                }

                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.status = Some(status);
                    stream.headers = regular_headers;

                    if (header.flags & flags::END_STREAM) != 0 {
                        self.complete_stream(stream_id);
                    }
                }
            }
            FrameType::Data => {
                let stream_id = header.stream_id;
                let end_stream = (header.flags & flags::END_STREAM) != 0;

                // Process flow control for inbound DATA frame.
                // The process_inbound_data_frame method takes stream_id, flags, and payload
                // to handle window updates and flow control state.
                let data = self
                    .connection
                    .process_inbound_data_frame(stream_id, header.flags, payload)
                    .await?;

                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.body.extend_from_slice(&data);

                    if end_stream {
                        self.complete_stream(stream_id);
                    }
                }
            }
            FrameType::WindowUpdate => {
                // Window update received and processed by handle_control_frame,
                // which updates the connection/stream window in self.connection.
                // Flush any pending data that was previously blocked by flow control.
                self.flush_pending_data().await?;
            }
            _ => {} // Other frames handled by handle_control_frame (or ignored)
        }

        Ok(())
    }

    /// Complete a stream: build response and send
    fn complete_stream(&mut self, stream_id: u32) {
        if let Some(mut stream) = self.streams.remove(&stream_id) {
            if let Some(tx) = stream.response_tx.take() {
                // If no status was received, this is a protocol violation
                // Return an error rather than defaulting to 200
                let response = match stream.status {
                    Some(status) => Ok(StreamResponse {
                        status,
                        headers: stream.headers,
                        body: stream.body.freeze(),
                    }),
                    None => Err(Error::HttpProtocol(format!(
                        "Stream {} completed without status code",
                        stream_id
                    ))),
                };
                if tx.send(response).is_err() {
                    tracing::debug!("Response channel closed while completing stream");
                }
            }
        }
        // Stream slot is now available. The main loop will call process_pending_requests
        // to process any queued requests waiting for available stream slots.
    }
}
