//! HTTP/3 connection driver - background task that reads packets and routes them to streams.
//!
//! The driver owns the QUIC connection and UdpSocket.

use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::sleep;
use tracing;

use crate::error::{Error, Result};
use quiche::h3::NameValue;

/// Command sent from handle to driver
#[derive(Debug)]
pub enum DriverCommand {
    /// Send a request and get response via oneshot
    SendRequest {
        method: http::Method,
        uri: http::Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
        response_tx: oneshot::Sender<Result<StreamResponse>>,
    },
}

#[derive(Debug)]
pub struct StreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
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

/// HTTP/3 connection driver
pub struct H3Driver {
    command_rx: mpsc::Receiver<DriverCommand>,
    conn: quiche::Connection,
    h3_conn: quiche::h3::Connection,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    streams: HashMap<u64, DriverStreamState>,
}

impl H3Driver {
    pub fn new(
        command_rx: mpsc::Receiver<DriverCommand>,
        conn: quiche::Connection,
        h3_conn: quiche::h3::Connection,
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            command_rx,
            conn,
            h3_conn,
            socket,
            peer_addr,
            streams: HashMap::new(),
        }
    }

    pub async fn drive(mut self) -> Result<()> {
        let mut buf = vec![0u8; 65535];
        let mut out = vec![0u8; 1350];

        loop {
            // 1. Process sending any pending packets first (egress)
            // quiche acts as state machine, we must flush generated packets
            loop {
                match self.conn.send(&mut out) {
                    Ok((len, _)) => {
                        if let Err(e) = self.socket.send_to(&out[..len], self.peer_addr).await {
                            tracing::error!("H3 socket send error: {}", e);
                            return Err(Error::Io(e));
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        tracing::error!("H3 quiche send error: {}", e);
                        return Err(Error::Quic(format!("QUIC send error: {}", e)));
                    }
                }
            }

            // 2. Select: Recv Packet OR Command OR Timeout
            // quiche::Connection::timeout() tells us how long until next timer event
            let timeout_duration = self.conn.timeout().unwrap_or(Duration::from_secs(60));

            tokio::select! {
                // Incoming Command
                cmd = self.command_rx.recv() => {
                    match cmd {
                        Some(c) => self.handle_command(c).await?,
                        None => {
                            // Driver dropped (all handles closed)
                            // Graceful shutdown? sending GOAWAY?
                            // For now just exit
                            match self.conn.close(true, 0x00, b"Client shutdown") {
                                Ok(_) => {},
                                Err(quiche::Error::Done) => {},
                                Err(_) => {}
                            }
                            // Flush close packet
                            while let Ok((len, _)) = self.conn.send(&mut out) {
                                let _ = self.socket.send_to(&out[..len], self.peer_addr).await;
                            }
                            return Ok(());
                        }
                    }
                }

                // Incoming Packet
                res = self.socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, from)) => {
                            if from == self.peer_addr {
                                let info = quiche::RecvInfo {
                                    from,
                                    to: self.socket.local_addr().unwrap(),
                                };
                                match self.conn.recv(&mut buf[..len], info) {
                                    Ok(_) => {
                                        // Process H3 events after receiving QUIC data
                                        self.process_h3_events()?;
                                    }
                                    Err(quiche::Error::Done) => {},
                                    Err(e) => {
                                        tracing::warn!("QUIC recv error: {}", e);
                                    }
                                }
                            }
                        }
                        Err(e) => return Err(Error::Io(e)),
                    }
                }

                // Timer
                _ = sleep(timeout_duration) => {
                    self.conn.on_timeout();
                }
            }
        }
    }

    async fn handle_command(&mut self, cmd: DriverCommand) -> Result<()> {
        match cmd {
            DriverCommand::SendRequest {
                method,
                uri,
                headers,
                body,
                response_tx,
            } => {
                // Construct H3 headers
                let path = uri.path();
                let path = if path.is_empty() { "/" } else { path };
                let host = uri.host().unwrap_or("").to_string();

                let mut h3_headers = vec![
                    quiche::h3::Header::new(b":method", method.as_str().as_bytes()),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", host.as_bytes()),
                    quiche::h3::Header::new(b":path", path.as_bytes()),
                ];

                for (k, v) in &headers {
                    let k_lower = k.to_lowercase();
                    // Filter pseudo and prohibited headers
                    if !k.starts_with(':')
                        && k_lower != "connection"
                        && k_lower != "keep-alive"
                        && k_lower != "proxy-connection"
                        && k_lower != "transfer-encoding"
                        && k_lower != "upgrade"
                    {
                        h3_headers.push(quiche::h3::Header::new(k.as_bytes(), v.as_bytes()));
                    }
                }

                // Send request logic
                let fin = body.is_none();
                match self.h3_conn.send_request(&mut self.conn, &h3_headers, fin) {
                    Ok(stream_id) => {
                        // Store stream state
                        let mut state = DriverStreamState::new(response_tx);

                        // Send body if present
                        if let Some(data) = body {
                            if let Err(e) =
                                self.h3_conn
                                    .send_body(&mut self.conn, stream_id, &data, true)
                            {
                                // Error sending body
                                if let Some(tx) = state.response_tx.take() {
                                    let _ = tx
                                        .send(Err(Error::Quic(format!("Send body failed: {}", e))));
                                }
                                return Ok(());
                            }
                        }

                        self.streams.insert(stream_id, state);
                    }
                    Err(e) => {
                        let _ = response_tx
                            .send(Err(Error::Quic(format!("Send request failed: {}", e))));
                    }
                }
            }
        }
        Ok(())
    }

    fn process_h3_events(&mut self) -> Result<()> {
        loop {
            match self.h3_conn.poll(&mut self.conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        for header in list {
                            let name = String::from_utf8_lossy(header.name());
                            let value = String::from_utf8_lossy(header.value());

                            if name == ":status" {
                                stream.status = value.parse().ok();
                            } else {
                                stream.headers.push((name.into_owned(), value.into_owned()));
                            }
                        }
                    }
                }
                Ok((stream_id, quiche::h3::Event::Data)) => {
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        let mut buf = vec![0u8; 65535];
                        while let Ok(len) =
                            self.h3_conn.recv_body(&mut self.conn, stream_id, &mut buf)
                        {
                            stream.body.extend_from_slice(&buf[..len]);
                        }
                    }
                }
                Ok((stream_id, quiche::h3::Event::Finished)) => {
                    if let Some(mut stream) = self.streams.remove(&stream_id) {
                        if let Some(tx) = stream.response_tx.take() {
                            let resp = StreamResponse {
                                status: stream.status.unwrap_or(0),
                                headers: stream.headers,
                                body: stream.body.freeze(),
                            };
                            let _ = tx.send(Ok(resp));
                        }
                    }
                }
                Ok((stream_id, quiche::h3::Event::Reset(error_code))) => {
                    if let Some(mut stream) = self.streams.remove(&stream_id) {
                        if let Some(tx) = stream.response_tx.take() {
                            let _ =
                                tx.send(Err(Error::Quic(format!("Stream reset: {}", error_code))));
                        }
                    }
                }
                Err(quiche::h3::Error::Done) => break,
                Ok(_) => {} // Ignore other events
                Err(e) => {
                    tracing::warn!("H3 poll error: {}", e);
                    return Err(Error::Quic(format!("H3 poll error: {}", e)));
                }
            }
        }
        Ok(())
    }
}
