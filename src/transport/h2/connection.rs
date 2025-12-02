//! HTTP/2 connection management.
//!
//! Handles the connection lifecycle, frame I/O, and stream multiplexing.

use bytes::{Buf, Bytes, BytesMut};
use http::{Method, Request, Response, StatusCode, Uri};
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::error::{Error, Result};
use crate::fingerprint::http2::Http2Settings;
use crate::response::Response as SpecterResponse;

use super::frame::*;
use super::hpack::{HpackDecoder, HpackEncoder, PseudoHeaderOrder};

/// Type alias for HTTP/2 errors (matches Error type).
pub type H2Error = Error;

/// Chrome's connection-level window increment.
/// Chrome sends WINDOW_UPDATE of 15663105 immediately after SETTINGS.
pub const CHROME_WINDOW_UPDATE: u32 = 15663105;

/// Initial window size per RFC 9113.
const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65535;

/// Threshold for sending WINDOW_UPDATE frames (16KB).
/// When receive window drops below this, send WINDOW_UPDATE.
const WINDOW_UPDATE_THRESHOLD: i32 = 16384;

/// Stream states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

/// Per-stream state.
struct Stream {
    id: u32,
    state: StreamState,
    recv_window: i32,
    send_window: i32,
    response_tx: Option<oneshot::Sender<Result<StreamResponse>>>,
    streaming_tx: Option<mpsc::Sender<std::result::Result<Bytes, H2Error>>>,
    response_headers: Vec<(String, String)>,
    response_data: BytesMut,
}

/// Response data collected for a stream.
pub struct StreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

/// HTTP/2 connection with full fingerprint control.
pub struct H2Connection<S> {
    /// Underlying stream (TLS socket).
    stream: S,
    /// HPACK encoder with custom pseudo-header order.
    encoder: HpackEncoder<'static>,
    /// HPACK decoder.
    decoder: HpackDecoder<'static>,
    /// Connection settings.
    settings: Http2Settings,
    /// Pseudo-header order for fingerprinting.
    pseudo_order: PseudoHeaderOrder,
    /// Next stream ID (client uses odd numbers).
    next_stream_id: u32,
    /// Active streams.
    streams: HashMap<u32, Stream>,
    /// Connection-level receive window.
    conn_recv_window: i32,
    /// Connection-level send window.
    conn_send_window: i32,
    /// Peer's settings.
    peer_settings: PeerSettings,
    /// Read buffer.
    read_buf: BytesMut,
    /// Buffer for accumulating header fragments when CONTINUATION frames are in progress.
    /// Format: (stream_id, accumulated_fragments)
    pending_headers: Option<(u32, BytesMut)>,
    /// GOAWAY received - last stream ID that server will process.
    /// RFC 9113 Section 6.8: Streams with ID <= last_stream_id can complete normally.
    goaway_last_stream_id: Option<u32>,
}

/// Peer's settings (received from server).
#[derive(Debug, Clone)]
struct PeerSettings {
    header_table_size: u32,
    enable_push: bool,
    max_concurrent_streams: u32,
    initial_window_size: u32,
    max_frame_size: u32,
    max_header_list_size: u32,
}

impl Default for PeerSettings {
    fn default() -> Self {
        Self {
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: u32::MAX,
            initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: u32::MAX,
        }
    }
}

impl<S> H2Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Create a new HTTP/2 connection.
    ///
    /// Performs the HTTP/2 handshake:
    /// 1. Send connection preface
    /// 2. Send SETTINGS frame with fingerprinted values
    /// 3. Send WINDOW_UPDATE for connection-level flow control
    /// 4. Wait for server SETTINGS and send ACK
    pub async fn connect(
        mut stream: S,
        settings: Http2Settings,
        pseudo_order: PseudoHeaderOrder,
    ) -> Result<Self> {
        // Build SETTINGS frame with Chrome fingerprint
        // CRITICAL: Chrome sends ALL 6 settings. Do NOT remove any.
        let mut settings_frame = SettingsFrame::new();
        settings_frame
            .set(SettingsId::HeaderTableSize, settings.header_table_size)
            .set(SettingsId::EnablePush, if settings.enable_push { 1 } else { 0 })
            .set(SettingsId::MaxConcurrentStreams, settings.max_concurrent_streams)
            .set(SettingsId::InitialWindowSize, settings.initial_window_size)
            .set(SettingsId::MaxFrameSize, settings.max_frame_size)
            .set(SettingsId::MaxHeaderListSize, settings.max_header_list_size);

        // Add GREASE setting (Chrome often sends 0x0a0a, 0x1a1a, etc.)
        // This helps look like a real browser and not a naive bot.
        settings_frame.set(0x0a0a_u16, 0);

        let settings_bytes = settings_frame.serialize();

        // Send WINDOW_UPDATE for connection-level window (Chrome behavior)
        let window_update = WindowUpdateFrame::new(0, CHROME_WINDOW_UPDATE);
        
        // Combine all handshake frames into a single write to minimize packets/TLS records
        let mut handshake_buf = BytesMut::new();
        handshake_buf.extend_from_slice(CONNECTION_PREFACE);
        handshake_buf.extend_from_slice(&settings_bytes);
        handshake_buf.extend_from_slice(&window_update.serialize());
        
        stream.write_all(&handshake_buf).await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send handshake: {}", e)))?;

        stream.flush().await
            .map_err(|e| Error::HttpProtocol(format!("Failed to flush: {}", e)))?;

        let conn = Self {
            stream,
            encoder: HpackEncoder::new(pseudo_order),
            decoder: HpackDecoder::new(),
            settings: settings.clone(),
            pseudo_order,
            next_stream_id: 1,
            streams: HashMap::new(),
            conn_recv_window: (DEFAULT_INITIAL_WINDOW_SIZE + CHROME_WINDOW_UPDATE) as i32,
            conn_send_window: DEFAULT_INITIAL_WINDOW_SIZE as i32,
            peer_settings: PeerSettings::default(),
            read_buf: BytesMut::with_capacity(16384),
            pending_headers: None,
            goaway_last_stream_id: None,
        };

        // Chrome behavior: Do NOT wait for server SETTINGS before sending requests.
        // Real browsers optimize by sending the request (HEADERS) immediately after the handshake
        // (in the same packet/flight if possible).
        // We skip waiting here; the server's SETTINGS frame will be handled by `read_response`
        // or `read_streaming_frames` when we start reading the response.
        
        /*
        match settings.handshake_timeout {
            Some(duration) => {
                match timeout(duration, conn.wait_for_settings()).await {
                    Ok(Ok(())) => {}, // Success
                    Ok(Err(e)) => return Err(e), // Connection error during handshake
                    Err(_) => {
                        // Timeout - send GOAWAY with SETTINGS_TIMEOUT before closing (RFC 9113)
                        let goaway = GoAwayFrame::new(0, ErrorCode::SettingsTimeout);
                        let _ = conn.stream.write_all(&goaway.serialize()).await;
                        let _ = conn.stream.flush().await;
                        return Err(Error::SettingsTimeout(duration));
                    }
                }
            }
            None => {
                // No timeout (not recommended for production)
                conn.wait_for_settings().await?;
            }
        }
        */

        Ok(conn)
    }

    /// Apply peer's settings.
    fn apply_peer_settings(&mut self, settings: &SettingsFrame) {
        for (id, value) in &settings.settings {
            match *id {
                0x1 => { // HeaderTableSize
                    self.peer_settings.header_table_size = *value;
                    self.encoder.set_max_table_size(*value as usize);
                }
                0x2 => { // EnablePush
                    self.peer_settings.enable_push = *value != 0;
                }
                0x3 => { // MaxConcurrentStreams
                    self.peer_settings.max_concurrent_streams = *value;
                }
                0x4 => { // InitialWindowSize
                    // RFC 9113 Section 6.5.2: INITIAL_WINDOW_SIZE must be <= 2^31-1
                    // RFC 9113 Section 6.9.2: When INITIAL_WINDOW_SIZE changes, adjust all stream windows
                    // Validate new window size (must be <= 2^31-1) before casting
                    if *value > i32::MAX as u32 {
                        continue; // Invalid setting, ignore per RFC 9113 Section 6.5.2
                    }
                    let old_size = self.peer_settings.initial_window_size as i32;
                    let new_size = *value as i32;
                    
                    let delta = new_size - old_size;
                    
                    self.peer_settings.initial_window_size = *value;
                    
                    // Adjust all existing stream send windows by delta
                    for stream in self.streams.values_mut() {
                        // RFC 9113 Section 6.9.2: Window can go negative, but must not exceed 2^31-1
                        let new_window = stream.send_window.saturating_add(delta);
                        stream.send_window = new_window;
                    }
                }
                0x5 => { // MaxFrameSize
                    // RFC 9113 Section 6.5.2: MAX_FRAME_SIZE must be between 16384 and 16777215
                    if *value < 16384 || *value > 16777215 {
                        continue; // Invalid setting, ignore per RFC 9113 Section 6.5.2
                    }
                    self.peer_settings.max_frame_size = *value;
                }
                0x6 => { // MaxHeaderListSize
                    self.peer_settings.max_header_list_size = *value;
                }
                _ => {} // Ignore unknown settings (including GREASE)
            }
        }
    }

    /// Send an HTTP/2 request and receive the response.
    pub async fn send_request(
        &mut self,
        method: Method,
        uri: &Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<SpecterResponse> {
        // Allocate stream ID
        // RFC 9113 Section 5.1.1: Client-initiated streams use odd-numbered stream IDs
        let stream_id = self.next_stream_id;
        if stream_id == 0 || (stream_id & 0x1) == 0 {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: Client stream ID must be odd and non-zero".into()
            ));
        }
        self.next_stream_id += 2; // Client uses odd stream IDs

        // Extract URI components
        let scheme = uri.scheme_str().unwrap_or("https");
        let authority = uri.authority()
            .map(|a| a.as_str())
            .unwrap_or("localhost");
        let path = uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        // RFC 9113 Section 8.1.2.3: Validate pseudo-header values
        if method.as_str().is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :method pseudo-header cannot be empty".into()
            ));
        }
        if scheme.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :scheme pseudo-header cannot be empty".into()
            ));
        }
        if authority.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :authority pseudo-header cannot be empty".into()
            ));
        }
        if path.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :path pseudo-header cannot be empty".into()
            ));
        }

        // Encode headers with custom pseudo-header order
        let header_block = self.encoder.encode_request(
            method.as_str(),
            scheme,
            authority,
            path,
            &headers,
        );

        // RFC 9113 Section 6.2: HEADERS frame header block must not be empty
        if header_block.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: HEADERS frame header block cannot be empty".into()
            ));
        }

        // Check if headers exceed max frame size and need CONTINUATION frames
        let max_frame_size = self.peer_settings.max_frame_size as usize;
        let end_stream = body.is_none();

        if header_block.len() <= max_frame_size {
            // Single HEADERS frame with END_HEADERS flag
            let headers_frame = HeadersFrame::new(stream_id, header_block)
                .end_stream(end_stream)
                .end_headers(true);

            self.stream.write_all(&headers_frame.serialize()).await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send HEADERS: {}", e)))?;
        } else {
            // Split across HEADERS + CONTINUATION frames
            let chunks: Vec<Bytes> = header_block
                .chunks(max_frame_size)
                .map(Bytes::copy_from_slice)
                .collect();

            // First: HEADERS without END_HEADERS
            let first_chunk = chunks[0].clone();
            let headers_frame = HeadersFrame::new(stream_id, first_chunk)
                .end_stream(end_stream)
                .end_headers(false);

            self.stream.write_all(&headers_frame.serialize()).await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send HEADERS: {}", e)))?;

            // Middle: CONTINUATION frames
            let num_chunks = chunks.len();
            for (idx, chunk) in chunks.into_iter().skip(1).enumerate() {
                let is_last = idx == num_chunks - 2; // -2 because we skipped first chunk
                let cont_frame = ContinuationFrame::new(
                    stream_id,
                    chunk,
                    is_last, // Only last chunk has END_HEADERS
                );
                self.stream.write_all(&cont_frame.serialize()).await
                    .map_err(|e| Error::HttpProtocol(format!("Failed to send CONTINUATION: {}", e)))?;
            }
        }

        // Send DATA frame if there's a body
        if let Some(body_data) = body {
            // Check send-side flow control
            let data_len = body_data.len() as i32;
            if self.conn_send_window < data_len {
                return Err(Error::HttpProtocol("Connection send window exhausted".into()));
            }
            if let Some(stream) = self.streams.get(&stream_id) {
                if stream.send_window < data_len {
                    return Err(Error::HttpProtocol("Stream send window exhausted".into()));
                }
            }
            
            let data_frame = DataFrame::new(stream_id, body_data).end_stream(true);
            self.stream.write_all(&data_frame.serialize()).await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send DATA: {}", e)))?;
            
            // Decrement send windows
            self.conn_send_window -= data_len;
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.send_window -= data_len;
            }
        }

        self.stream.flush().await
            .map_err(|e| Error::HttpProtocol(format!("Flush error: {}", e)))?;

        // Register stream
        let stream_state = if end_stream { StreamState::HalfClosedLocal } else { StreamState::Open };
        self.streams.insert(stream_id, Stream {
            id: stream_id,
            state: stream_state,
            recv_window: DEFAULT_INITIAL_WINDOW_SIZE as i32,
            send_window: DEFAULT_INITIAL_WINDOW_SIZE as i32,
            response_tx: None,
            streaming_tx: None,
            response_headers: Vec::new(),
            response_data: BytesMut::new(),
        });

        // Read response
        self.read_response(stream_id).await
    }

    /// Send request frames (HEADERS + optional DATA) and return stream ID.
    /// Internal helper for both send_request and send_request_streaming.
    async fn send_request_frames(&mut self, request: &Request<Bytes>) -> Result<u32> {
        // Allocate stream ID
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2; // Client uses odd stream IDs

        let uri = request.uri();
        let method = request.method();

        // Extract URI components
        let scheme = uri.scheme_str().unwrap_or("https");
        let authority = uri.authority()
            .map(|a| a.as_str())
            .unwrap_or("localhost");
        let path = uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        // RFC 9113 Section 8.1.2.3: Validate pseudo-header values
        if method.as_str().is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :method pseudo-header cannot be empty".into()
            ));
        }
        if scheme.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :scheme pseudo-header cannot be empty".into()
            ));
        }
        if authority.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :authority pseudo-header cannot be empty".into()
            ));
        }
        if path.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :path pseudo-header cannot be empty".into()
            ));
        }

        // Convert headers to Vec<(String, String)>
        let headers: Vec<(String, String)> = request.headers()
            .iter()
            .map(|(name, value)| {
                (name.to_string(), value.to_str().unwrap_or("").to_string())
            })
            .collect();

        // Encode headers with custom pseudo-header order
        let header_block = self.encoder.encode_request(
            method.as_str(),
            scheme,
            authority,
            path,
            &headers,
        );

        // RFC 9113 Section 6.2: HEADERS frame header block must not be empty
        if header_block.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: HEADERS frame header block cannot be empty".into()
            ));
        }

        // Check if headers exceed max frame size and need CONTINUATION frames
        let max_frame_size = self.peer_settings.max_frame_size as usize;
        let body = request.body();
        let end_stream = body.is_empty();

        if header_block.len() <= max_frame_size {
            // Single HEADERS frame with END_HEADERS flag
            let headers_frame = HeadersFrame::new(stream_id, header_block)
                .end_stream(end_stream)
                .end_headers(true);

            self.stream.write_all(&headers_frame.serialize()).await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send HEADERS: {}", e)))?;
        } else {
            // Split across HEADERS + CONTINUATION frames
            let chunks: Vec<Bytes> = header_block
                .chunks(max_frame_size)
                .map(Bytes::copy_from_slice)
                .collect();

            // First: HEADERS without END_HEADERS
            let first_chunk = chunks[0].clone();
            let headers_frame = HeadersFrame::new(stream_id, first_chunk)
                .end_stream(end_stream)
                .end_headers(false);

            self.stream.write_all(&headers_frame.serialize()).await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send HEADERS: {}", e)))?;

            // Middle: CONTINUATION frames
            let num_chunks = chunks.len();
            for (idx, chunk) in chunks.into_iter().skip(1).enumerate() {
                let is_last = idx == num_chunks - 2; // -2 because we skipped first chunk
                let cont_frame = ContinuationFrame::new(
                    stream_id,
                    chunk,
                    is_last, // Only last chunk has END_HEADERS
                );
                self.stream.write_all(&cont_frame.serialize()).await
                    .map_err(|e| Error::HttpProtocol(format!("Failed to send CONTINUATION: {}", e)))?;
            }
        }

        // Update stream state if END_STREAM was sent
        if end_stream {
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.state = StreamState::HalfClosedLocal;
            }
        }

        // Send DATA frame if there's a body
        if !body.is_empty() {
            // Check send-side flow control
            let data_len = body.len() as i32;
            if self.conn_send_window < data_len {
                return Err(Error::HttpProtocol("Connection send window exhausted".into()));
            }
            if let Some(stream) = self.streams.get(&stream_id) {
                if stream.send_window < data_len {
                    return Err(Error::HttpProtocol("Stream send window exhausted".into()));
                }
            }
            
            let data_frame = DataFrame::new(stream_id, body.clone()).end_stream(true);
            self.stream.write_all(&data_frame.serialize()).await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send DATA: {}", e)))?;
            
            // Decrement send windows
            self.conn_send_window -= data_len;
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.send_window -= data_len;
                stream.state = StreamState::HalfClosedLocal;
            }
        }

        self.stream.flush().await
            .map_err(|e| Error::HttpProtocol(format!("Flush error: {}", e)))?;

        Ok(stream_id)
    }

    /// Reads response with streaming body - yields headers then streams DATA frames incrementally.
    /// Returns (Response with empty body, Receiver for body chunks).
    /// Does NOT wait for END_STREAM before returning - streams data as it arrives.
    pub async fn send_request_streaming(
        &mut self,
        request: Request<Bytes>,
    ) -> std::result::Result<(Response<Bytes>, mpsc::Receiver<std::result::Result<Bytes, H2Error>>), Error> {
        // Send request frames (HEADERS with END_STREAM if no body)
        let stream_id = self.send_request_frames(&request).await?;

        // Create channel for streaming body chunks (32-buffer for backpressure)
        let (tx, rx) = mpsc::channel::<std::result::Result<Bytes, H2Error>>(32);

        // Register stream with streaming channel
        self.streams.insert(stream_id, Stream {
            id: stream_id,
            state: StreamState::Open,
            recv_window: DEFAULT_INITIAL_WINDOW_SIZE as i32,
            send_window: DEFAULT_INITIAL_WINDOW_SIZE as i32,
            response_tx: None,
            streaming_tx: Some(tx.clone()),
            response_headers: Vec::new(),
            response_data: BytesMut::new(),
        });

        // Read response headers (blocking until HEADERS frame received)
        let (status, headers) = self.read_response_headers(stream_id).await?;

        // Build response with empty body (actual body comes through rx channel)
        // Note: The caller must call read_streaming_frames() in a loop to process DATA frames
        // and send them through the channel. This allows non-blocking header return.
        let mut response_builder = Response::builder().status(status);
        for (name, value) in headers {
            response_builder = response_builder.header(name, value);
        }
        let response = response_builder.body(Bytes::new())
            .map_err(|e| Error::HttpProtocol(format!("Failed to build response: {}", e)))?;

        Ok((response, rx))
    }

    /// Reads and processes frames for streaming streams.
    /// Call this in a loop after send_request_streaming() to process incoming DATA frames.
    /// Returns Ok(true) if more frames expected, Ok(false) if stream ended, Err on error.
    /// This method checks all active streaming streams and routes DATA frames to their channels.
    pub async fn read_streaming_frames(&mut self) -> Result<bool> {
        // Read frame header
        while self.read_buf.len() < FRAME_HEADER_SIZE {
            let mut buf = [0u8; 16384];
            let n = self.stream.read(&mut buf).await
                .map_err(|e| Error::HttpProtocol(format!("Read error: {}", e)))?;
            if n == 0 {
                return Err(Error::HttpProtocol("Connection closed".into()));
            }
            self.read_buf.extend_from_slice(&buf[..n]);
        }

        let header = FrameHeader::parse(&self.read_buf[..FRAME_HEADER_SIZE])
            .ok_or_else(|| Error::HttpProtocol("Invalid frame header (reserved bits set)".into()))?;

        // RFC 9113 Section 4.2: Frame size validation
        if header.length > self.peer_settings.max_frame_size {
            return Err(Error::HttpProtocol(format!(
                "FRAME_SIZE_ERROR: Frame size {} exceeds MAX_FRAME_SIZE {}",
                header.length, self.peer_settings.max_frame_size
            )));
        }

        // Wait for full frame
        let frame_len = FRAME_HEADER_SIZE + header.length as usize;
        while self.read_buf.len() < frame_len {
            let mut buf = [0u8; 16384];
            let n = self.stream.read(&mut buf).await
                .map_err(|e| Error::HttpProtocol(format!("Read error: {}", e)))?;
            if n == 0 {
                return Err(Error::HttpProtocol("Connection closed".into()));
            }
            self.read_buf.extend_from_slice(&buf[..n]);
        }

        let payload_bytes = Bytes::from(self.read_buf[FRAME_HEADER_SIZE..frame_len].to_vec());
        self.read_buf.advance(frame_len);

        // Process frame - route to streaming channel if stream has streaming_tx
        self.process_streaming_frame(header, payload_bytes).await
    }

    /// Internal method to process incoming frames and route DATA frames to streaming channels.
    async fn process_streaming_frame(
        &mut self,
        header: FrameHeader,
        payload: Bytes,
    ) -> Result<bool> {
        match header.frame_type {
            FrameType::Data => {
                let stream_id = header.stream_id;
                
                // RFC 9113 Section 5.1: Validate stream ID (server-initiated streams use even IDs)
                // As a client, we should only receive DATA frames on streams we initiated (odd IDs)
                if (stream_id & 0x1) == 0 {
                    return Err(Error::HttpProtocol(
                        format!("PROTOCOL_ERROR: Received DATA frame on server-initiated stream {}", stream_id)
                    ));
                }

                let end_stream_flag = (header.flags & flags::END_STREAM) != 0;
                let is_streaming = self.streams.get(&stream_id)
                    .and_then(|s| s.streaming_tx.as_ref())
                    .is_some();

                if is_streaming {
                    // Parse DATA frame using proper parse method (handles padding)
                    let data_frame = DataFrame::parse(stream_id, header.flags, payload.clone())
                        .map_err(|e| Error::HttpProtocol(format!("Invalid DATA frame: {}", e)))?;

                    // Handle flow control (this may borrow self, so do it first)
                    self.handle_data_frame(&data_frame, stream_id).await?;

                    // Now get mutable access to send through channel
                    let should_end = if let Some(stream) = self.streams.get_mut(&stream_id) {
                        // Use stream.id to verify we're processing the right stream
                        if stream.id != stream_id {
                            return Err(Error::HttpProtocol("Stream ID mismatch".into()));
                        }
                        
                        if let Some(tx) = stream.streaming_tx.take() {
                            let send_result = tx.send(Ok(data_frame.data.clone())).await.is_ok();
                            if send_result && !end_stream_flag {
                                // Put tx back if stream not ended
                                stream.streaming_tx = Some(tx);
                            }
                            // Update state if END_STREAM
                            if end_stream_flag {
                                stream.state = match stream.state {
                                    StreamState::Open => StreamState::HalfClosedRemote,
                                    StreamState::HalfClosedLocal => StreamState::Closed,
                                    StreamState::HalfClosedRemote => {
                                        // Already half-closed remote, ignore duplicate END_STREAM
                                        StreamState::HalfClosedRemote
                                    }
                                    StreamState::Closed => {
                                        // Stream already closed, ignore
                                        StreamState::Closed
                                    }
                                };
                                stream.streaming_tx = None; // Signal end of stream
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    return Ok(!should_end); // Return false if stream ended
                }
                // Not a streaming stream, continue processing normally
                Ok(true)
            }
            FrameType::RstStream => {
                let stream_id = header.stream_id;
                // Parse RST_STREAM frame
                if let Ok(rst) = RstStreamFrame::parse(stream_id, payload.clone()) {
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        // Use stream.id to verify
                        if stream.id != stream_id {
                            return Err(Error::HttpProtocol("Stream ID mismatch in RST_STREAM".into()));
                        }
                        // RFC 9113 Section 5.1: RST_STREAM transitions stream to Closed
                        stream.state = StreamState::Closed;
                        if let Some(tx) = stream.streaming_tx.take() {
                            let _ = tx.send(Err(Error::HttpProtocol(format!(
                                "Stream reset by server: {:?}", rst.error_code
                            )))).await;
                        }
                        if let Some(tx) = stream.response_tx.take() {
                            let _ = tx.send(Err(Error::HttpProtocol(format!(
                                "Stream reset by server: {:?}", rst.error_code
                            ))));
                        }
                    }
                    self.streams.remove(&stream_id);
                    Ok(false) // Stream ended
                } else {
                    Err(Error::HttpProtocol("Invalid RST_STREAM frame".into()))
                }
            }
            FrameType::Priority => {
                // RFC 9113 Section 6.3: PRIORITY frames can be sent on any stream
                // Parse and validate (but we don't use priority information currently)
                if let Err(e) = PriorityFrame::parse(header.stream_id, payload.clone()) {
                    return Err(Error::HttpProtocol(format!("Invalid PRIORITY frame: {}", e)));
                }
                Ok(true) // Continue reading
            }
            FrameType::PushPromise => {
                // RFC 9113 Section 6.6: PUSH_PROMISE frames are only sent by servers
                // As a client, we should not receive these if ENABLE_PUSH is disabled
                if !self.peer_settings.enable_push {
                    return Err(Error::HttpProtocol(
                        "PROTOCOL_ERROR: Received PUSH_PROMISE but ENABLE_PUSH is disabled".into()
                    ));
                }
                // Parse and validate (but we don't support server push currently)
                if let Err(e) = PushPromiseFrame::parse(header.stream_id, header.flags, payload.clone()) {
                    return Err(Error::HttpProtocol(format!("Invalid PUSH_PROMISE frame: {}", e)));
                }
                // Server push is not supported, so we ignore the frame
                Ok(true) // Continue reading
            }
            _ => {
                // Handle control frames
                self.handle_control_frame(header.frame_type, header.stream_id, header.flags, &payload).await?;
                Ok(true) // Continue reading
            }
        }
    }

    /// Reads and parses HEADERS frame for a stream, returns (status, headers)
    async fn read_response_headers(
        &mut self,
        stream_id: u32,
    ) -> Result<(StatusCode, Vec<(String, String)>)> {
        loop {
            // Read frame header
            while self.read_buf.len() < FRAME_HEADER_SIZE {
                let mut buf = [0u8; 16384];
                let n = self.stream.read(&mut buf).await
                    .map_err(|e| Error::HttpProtocol(format!("Read error: {}", e)))?;
                if n == 0 {
                    return Err(Error::HttpProtocol("Connection closed".into()));
                }
                self.read_buf.extend_from_slice(&buf[..n]);
            }

            let header = FrameHeader::parse(&self.read_buf[..FRAME_HEADER_SIZE])
                .ok_or_else(|| Error::HttpProtocol("Invalid frame header (reserved bits set)".into()))?;

            // RFC 9113 Section 4.2: Frame size validation
            if header.length > self.peer_settings.max_frame_size {
                return Err(Error::HttpProtocol(format!(
                    "FRAME_SIZE_ERROR: Frame size {} exceeds MAX_FRAME_SIZE {}",
                    header.length, self.peer_settings.max_frame_size
                )));
            }

            // Wait for full frame
            let frame_len = FRAME_HEADER_SIZE + header.length as usize;
            while self.read_buf.len() < frame_len {
                let mut buf = [0u8; 16384];
                let n = self.stream.read(&mut buf).await
                    .map_err(|e| Error::HttpProtocol(format!("Read error: {}", e)))?;
                if n == 0 {
                    return Err(Error::HttpProtocol("Connection closed".into()));
                }
                self.read_buf.extend_from_slice(&buf[..n]);
            }

            let payload_bytes = Bytes::from(self.read_buf[FRAME_HEADER_SIZE..frame_len].to_vec());
            self.read_buf.advance(frame_len);

            match header.frame_type {
                FrameType::Headers => {
                    // RFC 9113 Section 5.1: Validate stream ID (server-initiated streams use even IDs)
                    // As a client, we should only receive HEADERS frames on streams we initiated (odd IDs)
                    if header.stream_id == stream_id {
                        if (header.stream_id & 0x1) == 0 {
                            return Err(Error::HttpProtocol(
                                format!("PROTOCOL_ERROR: Received HEADERS frame on server-initiated stream {}", header.stream_id)
                            ));
                        }

                        // Parse HEADERS frame using proper parse method (handles padding and priority)
                        let headers_frame = HeadersFrame::parse(header.stream_id, header.flags, payload_bytes.clone())
                            .map_err(|e| Error::HttpProtocol(format!("Invalid HEADERS frame: {}", e)))?;

                        let end_headers = headers_frame.end_headers;

                        if end_headers {
                            // Complete headers in single frame
                            let decoded = self.decoder.decode(&headers_frame.header_block)
                                .map_err(|e| Error::HttpProtocol(format!("HPACK decode error: {}", e)))?;

                            // Validate headers per RFC 9113 Section 8.1.2
                            Self::validate_response_headers(&decoded)?;

                            // Extract :status pseudo-header
                            let status = decoded
                                .iter()
                                .find(|(name, _)| name == ":status")
                                .and_then(|(_, value)| value.parse::<u16>().ok())
                                .ok_or_else(|| Error::HttpProtocol("Missing :status header".into()))?;

                            // Filter out pseudo-headers, keep only real headers
                            let real_headers: Vec<(String, String)> = decoded
                                .into_iter()
                                .filter(|(name, _)| !name.starts_with(':'))
                                .collect();

                            return Ok((StatusCode::from_u16(status)
                                .map_err(|_| Error::HttpProtocol("Invalid status code".into()))?, real_headers));
                        } else {
                            // Incomplete headers, expect CONTINUATION
                            if self.pending_headers.is_some() {
                                return Err(Error::HttpProtocol(
                                    "PROTOCOL_ERROR: received HEADERS while CONTINUATION pending".into()
                                ));
                            }
                            let mut fragments = BytesMut::new();
                            fragments.extend_from_slice(&headers_frame.header_block);
                            self.pending_headers = Some((header.stream_id, fragments));
                        }
                    }
                }
                FrameType::Continuation => {
                    if let Some((pending_stream_id, fragments)) = &mut self.pending_headers {
                        if *pending_stream_id == stream_id && *pending_stream_id == header.stream_id {
                            // Parse CONTINUATION frame using parse() method
                            let cont_frame = ContinuationFrame::parse(header.stream_id, header.flags, payload_bytes.clone())
                                .map_err(|e| Error::HttpProtocol(format!("Invalid CONTINUATION frame: {}", e)))?;
                            
                            fragments.extend_from_slice(&cont_frame.header_fragment);

                            if cont_frame.end_headers() {
                                // Complete! Decode accumulated headers
                                let decoded = self.decoder.decode(fragments)
                                    .map_err(|e| Error::HttpProtocol(format!("HPACK decode error: {}", e)))?;

                                // Extract :status pseudo-header
                                let status = decoded
                                    .iter()
                                    .find(|(name, _)| name == ":status")
                                    .and_then(|(_, value)| value.parse::<u16>().ok())
                                    .ok_or_else(|| Error::HttpProtocol("Missing :status header".into()))?;

                                // Filter out pseudo-headers, keep only real headers
                                let real_headers: Vec<(String, String)> = decoded
                                    .into_iter()
                                    .filter(|(name, _)| !name.starts_with(':'))
                                    .collect();

                                self.pending_headers = None;
                                return Ok((StatusCode::from_u16(status)
                                    .map_err(|_| Error::HttpProtocol("Invalid status code".into()))?, real_headers));
                            }
                        }
                    }
                }
                _ => {
                    // Handle other frames but continue looking for HEADERS
                    self.handle_control_frame(header.frame_type, header.stream_id, header.flags, &payload_bytes).await?;
                }
            }
        }
    }

    /// Handles control frames (SETTINGS, WINDOW_UPDATE, PING, etc.) that can arrive between HEADERS and DATA.
    async fn handle_control_frame(
        &mut self,
        frame_type: FrameType,
        stream_id: u32,
        flags: u8,
        payload: &Bytes,
    ) -> Result<()> {
        match frame_type {
            FrameType::Settings => {
                // RFC 9113 Section 6.5: SETTINGS frames MUST be on stream 0
                if stream_id != 0 {
                    return Err(Error::HttpProtocol(
                        "PROTOCOL_ERROR: SETTINGS frame must be on stream 0".into()
                    ));
                }
                if (flags & flags::ACK) == 0 {
                    let settings = SettingsFrame::parse(flags, payload.clone());
                    
                    // RFC 9113 Section 6.5: A SETTINGS frame MUST NOT contain multiple values for the same setting
                    let mut seen_settings = std::collections::HashSet::new();
                    for (id, _) in &settings.settings {
                        let id_u16 = *id;
                        if !seen_settings.insert(id_u16) {
                            return Err(Error::HttpProtocol(
                                format!("PROTOCOL_ERROR: Duplicate setting ID {} in SETTINGS frame", id_u16)
                            ));
                        }
                    }
                    
                    self.apply_peer_settings(&settings);
                    let ack = SettingsFrame::ack();
                    self.stream.write_all(&ack.serialize()).await.ok();
                    self.stream.flush().await.ok();
                }
            }
            FrameType::WindowUpdate => {
                if let Some(wu) = WindowUpdateFrame::parse(stream_id, payload.clone()) {
                    if wu.stream_id == 0 {
                        // Connection-level window update
                        self.conn_send_window += wu.increment as i32;
                    } else {
                        // Stream-level window update
                        if let Some(stream) = self.streams.get_mut(&wu.stream_id) {
                            stream.send_window += wu.increment as i32;
                        }
                    }
                }
            }
            FrameType::Ping => {
                if let Some(ping) = PingFrame::parse(flags, payload) {
                    if !ping.ack {
                        let pong = PingFrame::ack(ping.data);
                        self.stream.write_all(&pong.serialize()).await.ok();
                        self.stream.flush().await.ok();
                    }
                }
            }
            FrameType::GoAway => {
                // RFC 9113 Section 6.8: Store last_stream_id for graceful shutdown
                if let Some(goaway) = GoAwayFrame::parse(payload.clone()) {
                    self.goaway_last_stream_id = Some(goaway.last_stream_id);
                }
                // Don't return error - let in-flight streams complete
            }
            _ => {
                // Ignore other control frames during header reading
            }
        }
        Ok(())
    }


    /// Handles incoming DATA frame with proper flow control
    async fn handle_data_frame(
        &mut self,
        data_frame: &DataFrame,
        stream_id: u32,
    ) -> Result<()> {
        let payload_len = data_frame.data.len() as i32;

        // Decrement connection-level receive window
        self.conn_recv_window -= payload_len;

        // Decrement stream-level receive window
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            // Use stream.id to verify
            if stream.id != stream_id {
                return Err(Error::HttpProtocol("Stream ID mismatch in handle_data_frame".into()));
            }
            stream.recv_window -= payload_len;
        }

        // Send connection-level WINDOW_UPDATE when window gets low
        if self.conn_recv_window < WINDOW_UPDATE_THRESHOLD {
            let increment = DEFAULT_INITIAL_WINDOW_SIZE;
            self.send_window_update(0, increment).await?;
            self.conn_recv_window += increment as i32;
        }

        // Send stream-level WINDOW_UPDATE when window gets low
        let needs_stream_update = self.streams.get(&stream_id)
            .map(|s| {
                // Use stream.id to verify
                if s.id != stream_id {
                    return false;
                }
                s.recv_window < WINDOW_UPDATE_THRESHOLD
            })
            .unwrap_or(false);
        if needs_stream_update {
            let increment = DEFAULT_INITIAL_WINDOW_SIZE;
            if let Some(stream) = self.streams.get(&stream_id) {
                // Use stream.id for window update
                self.send_window_update(stream.id, increment).await?;
            }
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.recv_window += increment as i32;
            }
        }

        // Check END_STREAM flag to update state
        if data_frame.end_stream {
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.state = match stream.state {
                    StreamState::Open => StreamState::HalfClosedRemote,
                    StreamState::HalfClosedLocal => StreamState::Closed,
                    StreamState::HalfClosedRemote => {
                        // Already half-closed remote, ignore duplicate END_STREAM
                        StreamState::HalfClosedRemote
                    }
                    StreamState::Closed => {
                        // Stream already closed, ignore
                        StreamState::Closed
                    }
                };
            }
        }

        Ok(())
    }

    /// Sends WINDOW_UPDATE frame for connection (stream_id=0) or specific stream
    async fn send_window_update(&mut self, stream_id: u32, increment: u32) -> Result<()> {
        let frame = WindowUpdateFrame::new(stream_id, increment);
        self.stream.write_all(&frame.serialize()).await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send WINDOW_UPDATE: {}", e)))?;
        self.stream.flush().await
            .map_err(|e| Error::HttpProtocol(format!("Failed to flush WINDOW_UPDATE: {}", e)))?;
        Ok(())
    }

    /// Read response for a stream.
    async fn read_response(&mut self, stream_id: u32) -> Result<SpecterResponse> {
        let mut status = 0u16;
        let mut stream_done = false;
        
        // Verify stream exists and read stream.id
        if let Some(stream) = self.streams.get(&stream_id) {
            if stream.id != stream_id {
                return Err(Error::HttpProtocol("Stream ID mismatch".into()));
            }
        } else {
            return Err(Error::HttpProtocol("Stream not found".into()));
        }

        while !stream_done {
            // Read frame header
            while self.read_buf.len() < FRAME_HEADER_SIZE {
                let mut buf = [0u8; 16384];
                let n = self.stream.read(&mut buf).await
                    .map_err(|e| Error::HttpProtocol(format!("Read error: {}", e)))?;
                if n == 0 {
                    return Err(Error::HttpProtocol("Connection closed".into()));
                }
                self.read_buf.extend_from_slice(&buf[..n]);
            }

            let header = FrameHeader::parse(&self.read_buf[..FRAME_HEADER_SIZE])
                .ok_or_else(|| Error::HttpProtocol("Invalid frame header (reserved bits set)".into()))?;

            // RFC 9113 Section 4.2: Frame size validation
            if header.length > self.peer_settings.max_frame_size {
                return Err(Error::HttpProtocol(format!(
                    "FRAME_SIZE_ERROR: Frame size {} exceeds MAX_FRAME_SIZE {}",
                    header.length, self.peer_settings.max_frame_size
                )));
            }

            // Wait for full frame
            let frame_len = FRAME_HEADER_SIZE + header.length as usize;
            while self.read_buf.len() < frame_len {
                let mut buf = [0u8; 16384];
                let n = self.stream.read(&mut buf).await
                    .map_err(|e| Error::HttpProtocol(format!("Read error: {}", e)))?;
                if n == 0 {
                    return Err(Error::HttpProtocol("Connection closed".into()));
                }
                self.read_buf.extend_from_slice(&buf[..n]);
            }

            let payload_bytes = Bytes::from(self.read_buf[FRAME_HEADER_SIZE..frame_len].to_vec());
            self.read_buf.advance(frame_len);

            match header.frame_type {
                FrameType::Headers => {
                    // Check for PROTOCOL_ERROR: HEADERS received while CONTINUATION pending
                    if let Some((pending_stream_id, _)) = &self.pending_headers {
                        return Err(Error::HttpProtocol(
                            format!("PROTOCOL_ERROR: received HEADERS while CONTINUATION pending for stream {}", pending_stream_id)
                        ));
                    }

                    if header.stream_id != stream_id {
                        continue; // Different stream, ignore for now
                    }

                    // RFC 9113 Section 5.1: Validate stream ID (server-initiated streams use even IDs)
                    // As a client, we should only receive HEADERS frames on streams we initiated (odd IDs)
                    if (header.stream_id & 0x1) == 0 {
                        return Err(Error::HttpProtocol(
                            format!("PROTOCOL_ERROR: Received HEADERS frame on server-initiated stream {}", header.stream_id)
                        ));
                    }

                    // Parse HEADERS frame using proper parse method (handles padding and priority)
                    let headers_frame = HeadersFrame::parse(header.stream_id, header.flags, payload_bytes.clone())
                        .map_err(|e| Error::HttpProtocol(format!("Invalid HEADERS frame: {}", e)))?;

                    let end_headers = headers_frame.end_headers;

                    if end_headers {
                        // Complete headers in single frame
                        let decoded = self.decoder.decode(&headers_frame.header_block)
                            .map_err(|e| Error::HttpProtocol(format!("HPACK decode error: {}", e)))?;

                        // Validate headers per RFC 9113 Section 8.1.2
                        Self::validate_response_headers(&decoded)?;

                        if let Some(stream) = self.streams.get_mut(&stream_id) {
                            // Use stream.id to verify
                            if stream.id != stream_id {
                                return Err(Error::HttpProtocol("Stream ID mismatch".into()));
                            }
                            for (name, value) in decoded {
                                if name == ":status" {
                                    status = value.parse().unwrap_or(0);
                                } else if !name.starts_with(':') {
                                    // Read and write to stream.response_headers
                                    stream.response_headers.push((name, value));
                                }
                            }
                        }
                    } else {
                        // Incomplete headers, expect CONTINUATION
                        if self.pending_headers.is_some() {
                            return Err(Error::HttpProtocol(
                                "PROTOCOL_ERROR: received HEADERS while CONTINUATION pending".into()
                            ));
                        }
                        let mut fragments = BytesMut::new();
                        fragments.extend_from_slice(&headers_frame.header_block);
                        self.pending_headers = Some((header.stream_id, fragments));
                    }

                    if headers_frame.end_stream {
                        stream_done = true;
                    }
                }
                FrameType::Continuation => {
                    match &mut self.pending_headers {
                        None => {
                            return Err(Error::HttpProtocol(
                                "PROTOCOL_ERROR: CONTINUATION without preceding HEADERS".into()
                            ));
                        }
                        Some((pending_stream_id, fragments)) => {
                            if *pending_stream_id != header.stream_id {
                                return Err(Error::HttpProtocol(
                                    format!("PROTOCOL_ERROR: CONTINUATION stream_id {} does not match pending HEADERS stream_id {}", header.stream_id, pending_stream_id)
                                ));
                            }

                            // Parse CONTINUATION frame using parse() method
                            let cont_frame = ContinuationFrame::parse(header.stream_id, header.flags, payload_bytes.clone())
                                .map_err(|e| Error::HttpProtocol(format!("Invalid CONTINUATION frame: {}", e)))?;
                            
                            // Append fragment
                            fragments.extend_from_slice(&cont_frame.header_fragment);

                            if cont_frame.end_headers() {
                                // Complete! Decode accumulated headers
                                // Only process if this is for our stream
                                if header.stream_id == stream_id {
                                    let decoded = self.decoder.decode(fragments)
                                        .map_err(|e| Error::HttpProtocol(format!("HPACK decode error: {}", e)))?;

                                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                                        // Use stream.id to verify
                                        if stream.id != stream_id {
                                            return Err(Error::HttpProtocol("Stream ID mismatch".into()));
                                        }
                                        for (name, value) in decoded {
                                            if name == ":status" {
                                                status = value.parse().unwrap_or(0);
                                            } else if !name.starts_with(':') {
                                                // Read and write to stream.response_headers
                                                stream.response_headers.push((name, value));
                                            }
                                        }
                                    }
                                }
                                // Clear pending headers
                                self.pending_headers = None;
                            }
                            // Otherwise, more CONTINUATION frames expected
                        }
                    }
                }
                FrameType::Data => {
                    // Check for PROTOCOL_ERROR: DATA received during CONTINUATION sequence
                    if let Some((pending_stream_id, _)) = &self.pending_headers {
                        return Err(Error::HttpProtocol(
                            format!("PROTOCOL_ERROR: received DATA during CONTINUATION sequence for stream {}", pending_stream_id)
                        ));
                    }

                    if header.stream_id != stream_id {
                        continue;
                    }

                    // RFC 9113 Section 5.1: Validate stream ID (server-initiated streams use even IDs)
                    // As a client, we should only receive DATA frames on streams we initiated (odd IDs)
                    if (header.stream_id & 0x1) == 0 {
                        return Err(Error::HttpProtocol(
                            format!("PROTOCOL_ERROR: Received DATA frame on server-initiated stream {}", header.stream_id)
                        ));
                    }

                    // Parse DATA frame using proper parse method (handles padding)
                    let data_frame = DataFrame::parse(header.stream_id, header.flags, payload_bytes.clone())
                        .map_err(|e| Error::HttpProtocol(format!("Invalid DATA frame: {}", e)))?;

                    // Handle flow control (decrement windows, send WINDOW_UPDATE if needed)
                    self.handle_data_frame(&data_frame, stream_id).await?;

                    // Read and write to stream.response_data
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        // Use stream.id to verify
                        if stream.id != stream_id {
                            return Err(Error::HttpProtocol("Stream ID mismatch".into()));
                        }
                        stream.response_data.extend_from_slice(&data_frame.data);
                    }

                    if data_frame.end_stream {
                        stream_done = true;
                    }
                }
                FrameType::Settings => {
                    // RFC 9113 Section 6.5: SETTINGS frames MUST be on stream 0
                    if header.stream_id != 0 {
                        return Err(Error::HttpProtocol(
                            "PROTOCOL_ERROR: SETTINGS frame must be on stream 0".into()
                        ));
                    }
                    // Settings frames on stream 0 are allowed during CONTINUATION
                    if (header.flags & flags::ACK) == 0 {
                        // Server settings update
                        let settings = SettingsFrame::parse(header.flags, payload_bytes.clone());
                        
                        // RFC 9113 Section 6.5: A SETTINGS frame MUST NOT contain multiple values for the same setting
                        let mut seen_settings = std::collections::HashSet::new();
                        for (id, _) in &settings.settings {
                            let id_u16 = *id;
                            if !seen_settings.insert(id_u16) {
                                return Err(Error::HttpProtocol(
                                    format!("PROTOCOL_ERROR: Duplicate setting ID {} in SETTINGS frame", id_u16)
                                ));
                            }
                        }
                        
                        self.apply_peer_settings(&settings);

                        // Send ACK
                        let ack = SettingsFrame::ack();
                        self.stream.write_all(&ack.serialize()).await.ok();
                        self.stream.flush().await.ok();
                    }
                }
            FrameType::WindowUpdate => {
                // WindowUpdate frames on stream 0 are allowed during CONTINUATION
                if let Some(wu) = WindowUpdateFrame::parse(header.stream_id, payload_bytes.clone()) {
                    if wu.stream_id == 0 {
                        // Connection-level window update
                        // Increment validated in parse() (must be > 0)
                        self.conn_send_window += wu.increment as i32;
                    } else {
                        if self.pending_headers.is_some() {
                            // WindowUpdate on non-zero stream during CONTINUATION is PROTOCOL_ERROR
                            return Err(Error::HttpProtocol(
                                "PROTOCOL_ERROR: received WINDOW_UPDATE during CONTINUATION sequence".into()
                            ));
                        }
                        // Stream-level window update
                        // Increment validated in parse() (must be > 0)
                        if let Some(stream) = self.streams.get_mut(&wu.stream_id) {
                            stream.send_window += wu.increment as i32;
                        }
                    }
                } else {
                    // Invalid WINDOW_UPDATE (e.g., increment = 0)
                    return Err(Error::HttpProtocol(
                        "FLOW_CONTROL_ERROR: WINDOW_UPDATE increment must be > 0".into()
                    ));
                }
            }
                FrameType::Ping => {
                    // Ping frames on stream 0 are allowed during CONTINUATION
                    if let Some(ping) = PingFrame::parse(header.flags, &payload_bytes) {
                        if !ping.ack {
                            // Respond to PING
                            let pong = PingFrame::ack(ping.data);
                            self.stream.write_all(&pong.serialize()).await.ok();
                            self.stream.flush().await.ok();
                        }
                    }
                }
                FrameType::GoAway => {
                    // RFC 9113 Section 6.8: GOAWAY allows graceful shutdown
                    // Streams with ID <= last_stream_id can complete normally
                    if let Some(goaway) = GoAwayFrame::parse(payload_bytes.clone()) {
                        self.goaway_last_stream_id = Some(goaway.last_stream_id);

                        // If current stream is allowed to complete, continue reading
                        if stream_id <= goaway.last_stream_id && goaway.error_code == ErrorCode::NoError {
                            // Graceful shutdown - allow stream to complete
                            continue;
                        }

                        // Stream refused or connection error
                        return Err(Error::HttpProtocol(format!(
                            "Server sent GOAWAY: {:?}, last_stream_id={}, current_stream={}",
                            goaway.error_code, goaway.last_stream_id, stream_id
                        )));
                    }
                }
                FrameType::Priority => {
                    // RFC 9113 Section 6.3: PRIORITY frames can be sent on any stream
                    // Parse and validate (but we don't use priority information currently)
                    if let Err(e) = PriorityFrame::parse(header.stream_id, payload_bytes.clone()) {
                        return Err(Error::HttpProtocol(format!("Invalid PRIORITY frame: {}", e)));
                    }
                    // Priority information is parsed and validated, but not used for now
                }
                FrameType::PushPromise => {
                    // RFC 9113 Section 6.6: PUSH_PROMISE frames are only sent by servers
                    // As a client, we should not receive these if ENABLE_PUSH is disabled
                    if !self.peer_settings.enable_push {
                        return Err(Error::HttpProtocol(
                            "PROTOCOL_ERROR: Received PUSH_PROMISE but ENABLE_PUSH is disabled".into()
                        ));
                    }
                    // Parse and validate (but we don't support server push currently)
                    if let Err(e) = PushPromiseFrame::parse(header.stream_id, header.flags, payload_bytes.clone()) {
                        return Err(Error::HttpProtocol(format!("Invalid PUSH_PROMISE frame: {}", e)));
                    }
                    // Server push is not supported, so we ignore the frame
                    // In a full implementation, we would handle the promised stream
                }
                FrameType::RstStream => {
                    if header.stream_id == stream_id {
                        // Parse RST_STREAM frame
                        if let Ok(rst) = RstStreamFrame::parse(header.stream_id, payload_bytes.clone()) {
                            // RFC 9113 Section 5.1: RST_STREAM transitions stream to Closed
                            if let Some(stream) = self.streams.get_mut(&stream_id) {
                                stream.state = StreamState::Closed;
                            }
                            // Clear pending headers if any
                            if let Some((pending_stream_id, _)) = &self.pending_headers {
                                if *pending_stream_id == stream_id {
                                    self.pending_headers = None;
                                }
                            }
                            return Err(Error::HttpProtocol(format!(
                                "Stream {} reset by server: {:?}", stream_id, rst.error_code
                            )));
                        } else {
                            return Err(Error::HttpProtocol("Invalid RST_STREAM frame".into()));
                        }
                    } else if self.pending_headers.is_some() {
                        // RST_STREAM on different stream during CONTINUATION is PROTOCOL_ERROR
                        return Err(Error::HttpProtocol(
                            "PROTOCOL_ERROR: received RST_STREAM during CONTINUATION sequence".into()
                        ));
                    }
                }
                _ => {
                    // Any other frame type during CONTINUATION sequence is PROTOCOL_ERROR
                    if self.pending_headers.is_some() {
                        return Err(Error::HttpProtocol(
                            format!("PROTOCOL_ERROR: received {:?} during CONTINUATION sequence", header.frame_type)
                        ));
                    }
                }
            }
        }

        // Read stream fields and create StreamResponse
        let (final_headers, final_body) = if let Some(stream) = self.streams.get_mut(&stream_id) {
            // Read all stream fields
            let headers = stream.response_headers.clone();
            let body = stream.response_data.clone();
            
            // Create StreamResponse and send through channel if stream has response_tx
            if let Some(tx) = stream.response_tx.take() {
                let response = StreamResponse {
                    status,
                    headers: headers.clone(),
                    body: body.clone().freeze(),
                };
                let _ = tx.send(Ok(response));
            }
            
            (headers, body)
        } else {
            (Vec::new(), BytesMut::new())
        };

        // Clean up stream
        self.streams.remove(&stream_id);

        // Convert headers to string format for SpecterResponse
        let response_headers_str: Vec<String> = final_headers.iter()
            .map(|(name, value)| format!("{}: {}", name, value))
            .collect();

        Ok(SpecterResponse::new(
            status,
            response_headers_str,
            final_body.freeze(),
            "HTTP/2".to_string(),
        ))
    }

    /// Get the pseudo-header order.
    pub fn pseudo_order(&self) -> PseudoHeaderOrder {
        self.pseudo_order
    }

    /// Get the settings.
    pub fn settings(&self) -> &Http2Settings {
        &self.settings
    }

    /// Validate response headers per RFC 9113 Section 8.1.2.
    /// Ensures required pseudo-headers are present and properly formatted.
    fn validate_response_headers(headers: &[(String, String)]) -> Result<()> {
        let mut has_status = false;
        let mut seen_pseudo = std::collections::HashSet::new();

        for (name, value) in headers {
            if name.starts_with(':') {
                // Pseudo-header validation
                if seen_pseudo.contains(name) {
                    return Err(Error::HttpProtocol(
                        format!("PROTOCOL_ERROR: Duplicate pseudo-header: {}", name)
                    ));
                }
                seen_pseudo.insert(name.clone());

                match name.as_str() {
                    ":status" => {
                        has_status = true;
                        // Validate status code format (3-digit number)
                        if value.len() != 3 || !value.chars().all(|c| c.is_ascii_digit()) {
                            return Err(Error::HttpProtocol(
                                format!("PROTOCOL_ERROR: Invalid :status value: {}", value)
                            ));
                        }
                    }
                    ":method" | ":scheme" | ":authority" | ":path" => {
                        // These pseudo-headers should not appear in responses
                        return Err(Error::HttpProtocol(
                            format!("PROTOCOL_ERROR: Request pseudo-header {} in response", name)
                        ));
                    }
                    _ => {
                        // Unknown pseudo-header
                        return Err(Error::HttpProtocol(
                            format!("PROTOCOL_ERROR: Unknown pseudo-header: {}", name)
                        ));
                    }
                }
            } else {
                // Regular header validation
                // RFC 9113 Section 8.1.2: Connection-specific headers are forbidden
                let name_lower = name.to_lowercase();
                if name_lower == "connection"
                    || name_lower == "keep-alive"
                    || name_lower == "proxy-connection"
                    || name_lower == "transfer-encoding"
                    || name_lower == "upgrade"
                {
                    return Err(Error::HttpProtocol(
                        format!("PROTOCOL_ERROR: Connection-specific header forbidden: {}", name)
                    ));
                }
            }
        }

        if !has_status {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: Missing required :status pseudo-header".into()
            ));
        }

        Ok(())
    }
}
