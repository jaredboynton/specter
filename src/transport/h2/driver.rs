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
use crate::transport::h2::frame::{flags, FrameHeader, FrameType};

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
}

impl DriverStreamState {
    fn new(response_tx: oneshot::Sender<Result<StreamResponse>>) -> Self {
        Self {
            response_tx: Some(response_tx),
            status: None,
            headers: Vec::new(),
            body: BytesMut::new(),
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
                                    eprintln!("Streaming requests not yet implemented in driver");
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
                                // If protocol error, maybe shutdown?
                                // For now we assume connection might be usable or closed by peer.
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
            let req = match req_builder.body(body_bytes) {
                Ok(r) => r,
                Err(e) => {
                    let _ = response_tx
                        .send(Err(Error::HttpProtocol(format!("Invalid request: {}", e))));
                    return Ok(());
                }
            };

            // Send frame (non-blocking write)
            match self.connection.send_request_frames(&req).await {
                Ok(stream_id) => {
                    // Register stream state
                    self.streams
                        .insert(stream_id, DriverStreamState::new(response_tx));
                }
                Err(e) => {
                    // Notify error immediately
                    let _ = response_tx.send(Err(e));
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
                        let _ = tx.send(Err(Error::HttpProtocol(format!(
                            "Stream reset by peer: {:?}",
                            code
                        ))));
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
                                let _ = tx.send(Err(Error::HttpProtocol("GOAWAY received".into())));
                            }
                        }
                    }
                }
                // We could choose to shutdown driver here, but maybe wait for current streams?
                return Ok(());
            }
            ControlAction::None => {
                // Continue to specific processing
            }
        }

        // 2. Data / Headers routing
        match header.frame_type {
            FrameType::Headers => {
                let stream_id = header.stream_id;

                // Handle CONTINUATION if needed (END_HEADERS not set)
                // If this is a CONTINUATION frame, we shouldn't be here (block collected it)
                // But this is the start of a header block (HEADERS frame)
                if (header.flags & flags::END_HEADERS) == 0 {
                    // Loop to read CONTINUATION frames
                    // NOTE: This inner loop blocks the driver select! but expected per RFC
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

                // Process flow control
                // We must pass flags? handle_data_frame parses flags from frame header?
                // No, process_inbound_data_frame takes (stream_id, flags, payload).
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
            _ => {} // Other frames handled by handle_control_frame (or ignored)
        }

        Ok(())
    }

    /// Complete a stream: build response and send
    fn complete_stream(&mut self, stream_id: u32) {
        if let Some(mut stream) = self.streams.remove(&stream_id) {
            if let Some(tx) = stream.response_tx.take() {
                let status = stream.status.unwrap_or(200); // Default/Error?
                let response = StreamResponse {
                    status,
                    headers: stream.headers,
                    body: stream.body.freeze(),
                };
                let _ = tx.send(Ok(response));
            }
        }
        // Slot freed, check queue - but this is called from drive loop which calls process_pending
        // We can't await here easily if we are in sync context? No, complete_stream is synchronous helper?
        // Ah, complete_stream is called from async handle_frame.
        // But complete_stream is not async.
        // We should call self.process_pending_requests() after complete_stream usage in handle_frame.
        // Or make complete_stream async.
        // Actually, drive loop calls handle_frame, which calls complete_stream.
        // We should just call process_pending_requests at the top of the loop.
        // But that might delay picking up a new request until next iteration.
        // Let's rely on the loop top check for now.
    }
}
