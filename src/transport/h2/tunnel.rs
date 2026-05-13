use bytes::Bytes;
use tokio::sync::mpsc;

use crate::error::{Error, Result};

/// Outbound bytes queued by an RFC 8441 tunnel handle for the H2 driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2TunnelOutbound {
    pub bytes: Bytes,
    pub end_stream: bool,
}

/// Inbound tunnel event delivered by the H2 driver to the tunnel handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H2TunnelEvent {
    Data(Bytes),
    EndStream,
    Reset(String),
    GoAway { last_stream_id: u32 },
}

/// Byte transport for an RFC 8441 tunnel stream.
#[derive(Debug)]
pub struct H2Tunnel {
    outbound_tx: mpsc::Sender<H2TunnelOutbound>,
    inbound_rx: mpsc::Receiver<Result<H2TunnelEvent>>,
}

impl H2Tunnel {
    pub fn new(
        outbound_tx: mpsc::Sender<H2TunnelOutbound>,
        inbound_rx: mpsc::Receiver<Result<H2TunnelEvent>>,
    ) -> Self {
        Self {
            outbound_tx,
            inbound_rx,
        }
    }

    pub async fn send_bytes(&self, bytes: Bytes, end_stream: bool) -> Result<()> {
        self.outbound_tx
            .send(H2TunnelOutbound { bytes, end_stream })
            .await
            .map_err(|_| Error::HttpProtocol("H2 tunnel outbound channel closed".into()))
    }

    pub async fn close_send(&self) -> Result<()> {
        self.send_bytes(Bytes::new(), true).await
    }

    pub async fn recv_event(&mut self) -> Option<Result<H2TunnelEvent>> {
        self.inbound_rx.recv().await
    }

    pub async fn recv_bytes(&mut self) -> Option<Result<Bytes>> {
        loop {
            match self.recv_event().await? {
                Ok(H2TunnelEvent::Data(bytes)) => return Some(Ok(bytes)),
                Ok(H2TunnelEvent::EndStream) => return None,
                Ok(H2TunnelEvent::Reset(reason)) => {
                    return Some(Err(Error::HttpProtocol(format!(
                        "H2 tunnel reset: {reason}"
                    ))));
                }
                Ok(H2TunnelEvent::GoAway { last_stream_id }) => {
                    return Some(Err(Error::HttpProtocol(format!(
                        "H2 tunnel closed by GOAWAY last_stream_id={last_stream_id}"
                    ))));
                }
                Err(err) => return Some(Err(err)),
            }
        }
    }
}
