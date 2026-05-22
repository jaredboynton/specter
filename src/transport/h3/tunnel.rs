use bytes::Bytes;
use tokio::sync::mpsc;

use crate::error::{Error, Result};

/// Outbound bytes queued by an RFC 9220 tunnel handle for the H3 driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3TunnelOutbound {
    pub bytes: Bytes,
    pub fin: bool,
}

/// Inbound tunnel event delivered by the H3 driver to the tunnel handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3TunnelEvent {
    Data(Bytes),
    EndStream,
    Reset(String),
    GoAway { id: u64 },
}

/// Byte transport for an RFC 9220 WebSocket-over-HTTP/3 tunnel stream.
#[derive(Debug)]
pub struct H3Tunnel {
    outbound_tx: mpsc::Sender<H3TunnelOutbound>,
    inbound_rx: mpsc::Receiver<Result<H3TunnelEvent>>,
}

impl H3Tunnel {
    pub fn new(
        outbound_tx: mpsc::Sender<H3TunnelOutbound>,
        inbound_rx: mpsc::Receiver<Result<H3TunnelEvent>>,
    ) -> Self {
        Self {
            outbound_tx,
            inbound_rx,
        }
    }

    pub async fn send_bytes(&self, bytes: Bytes, fin: bool) -> Result<()> {
        self.outbound_tx
            .send(H3TunnelOutbound { bytes, fin })
            .await
            .map_err(|_| Error::HttpProtocol("H3 tunnel outbound channel closed".into()))
    }

    pub async fn close_send(&self) -> Result<()> {
        self.send_bytes(Bytes::new(), true).await
    }

    pub async fn recv_event(&mut self) -> Option<Result<H3TunnelEvent>> {
        self.inbound_rx.recv().await
    }

    pub async fn recv_bytes(&mut self) -> Option<Result<Bytes>> {
        match self.recv_event().await? {
            Ok(H3TunnelEvent::Data(bytes)) => Some(Ok(bytes)),
            Ok(H3TunnelEvent::EndStream) => None,
            Ok(H3TunnelEvent::Reset(reason)) => Some(Err(Error::HttpProtocol(format!(
                "H3 tunnel reset: {reason}"
            )))),
            Ok(H3TunnelEvent::GoAway { id }) => Some(Err(Error::HttpProtocol(format!(
                "H3 tunnel closed by GOAWAY id={id}"
            )))),
            Err(err) => Some(Err(err)),
        }
    }
}
