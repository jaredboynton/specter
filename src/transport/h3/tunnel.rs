use bytes::Bytes;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Notify;

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

#[derive(Debug)]
pub(crate) struct H3TunnelCredit {
    released_recv_bytes: AtomicUsize,
    driver_notify: Arc<Notify>,
}

impl H3TunnelCredit {
    pub(crate) fn new(driver_notify: Arc<Notify>) -> Arc<Self> {
        Arc::new(Self {
            released_recv_bytes: AtomicUsize::new(0),
            driver_notify,
        })
    }

    pub(crate) fn take_released_recv_bytes(&self) -> usize {
        self.released_recv_bytes.swap(0, Ordering::Relaxed)
    }
}

/// Byte transport for an RFC 9220 WebSocket-over-HTTP/3 tunnel stream.
#[derive(Debug)]
pub struct H3Tunnel {
    outbound_tx: mpsc::Sender<H3TunnelOutbound>,
    inbound_rx: mpsc::Receiver<Result<H3TunnelEvent>>,
    credit: Option<Arc<H3TunnelCredit>>,
}

impl H3Tunnel {
    pub fn new(
        outbound_tx: mpsc::Sender<H3TunnelOutbound>,
        inbound_rx: mpsc::Receiver<Result<H3TunnelEvent>>,
    ) -> Self {
        Self {
            outbound_tx,
            inbound_rx,
            credit: None,
        }
    }

    pub(crate) fn new_with_credit(
        outbound_tx: mpsc::Sender<H3TunnelOutbound>,
        inbound_rx: mpsc::Receiver<Result<H3TunnelEvent>>,
        credit: Arc<H3TunnelCredit>,
    ) -> Self {
        Self {
            outbound_tx,
            inbound_rx,
            credit: Some(credit),
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
        let event = self.inbound_rx.recv().await?;
        if let Ok(H3TunnelEvent::Data(bytes)) = &event {
            self.release_recv_bytes(bytes.len());
        } else if let Some(credit) = self.credit.as_ref() {
            credit.driver_notify.notify_one();
        }
        Some(event)
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

    fn release_recv_bytes(&self, released: usize) {
        let Some(credit) = self.credit.as_ref() else {
            return;
        };
        if released > 0 {
            credit
                .released_recv_bytes
                .fetch_add(released, Ordering::Relaxed);
        }
        credit.driver_notify.notify_one();
    }
}
