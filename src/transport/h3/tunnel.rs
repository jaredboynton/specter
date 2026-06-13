use bytes::Bytes;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::Notify;

use crate::error::{Error, Result};
use crate::transport::h3::handle::H3DirectDriverSlot;
use crate::transport::h3::native::data_frame_encoded_len;
use crate::transport::h3::native_driver::NativeH3Driver;

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

#[derive(Debug, Default)]
pub(crate) struct H3TunnelInlineInbound {
    queue: StdMutex<VecDeque<Result<H3TunnelEvent>>>,
}

impl H3TunnelInlineInbound {
    pub(crate) fn push(&self, event: Result<H3TunnelEvent>) {
        if let Ok(mut queue) = self.queue.lock() {
            queue.push_back(event);
        }
    }

    pub(crate) fn pop(&self) -> Option<Result<H3TunnelEvent>> {
        self.queue.lock().ok()?.pop_front()
    }
}

/// Cap on the outbound byte budget. Keeping the cap at `u32::MAX` preserves
/// the old semaphore-era bound while letting the hot path use atomic counters.
pub(crate) const MAX_TUNNEL_OUTBOUND_BYTE_BUDGET: usize = u32::MAX as usize;
pub(crate) const MAX_TUNNEL_INBOUND_BYTE_BUDGET: usize = u32::MAX as usize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct H3TunnelCapacity {
    pub outbound_budget: usize,
    pub outbound_available_bytes: usize,
    pub outbound_pending_bytes: usize,
    pub inbound_budget: usize,
    pub inbound_available_bytes: usize,
    pub inbound_pending_bytes: usize,
}

#[derive(Debug)]
pub(crate) struct H3TunnelCredit {
    released_recv_bytes: AtomicUsize,
    driver_notify: Arc<Notify>,
    /// Bytes still available to push into the outbound pipeline
    /// (`H3Tunnel` channel + driver `pending_outbound` queue + in-flight wire
    /// bytes). The hot path is an atomic decrement; only exhausted credit waits
    /// on `send_notify`.
    send_available: AtomicUsize,
    send_notify: Notify,
    send_budget: usize,
    recv_available: AtomicUsize,
    recv_budget: usize,
}

impl H3TunnelCredit {
    pub(crate) fn new(
        driver_notify: Arc<Notify>,
        send_budget: usize,
        recv_budget: usize,
    ) -> Arc<Self> {
        let send_budget = send_budget.min(MAX_TUNNEL_OUTBOUND_BYTE_BUDGET);
        let recv_budget = recv_budget.min(MAX_TUNNEL_INBOUND_BYTE_BUDGET);
        Arc::new(Self {
            released_recv_bytes: AtomicUsize::new(0),
            driver_notify,
            send_available: AtomicUsize::new(send_budget),
            send_notify: Notify::new(),
            send_budget,
            recv_available: AtomicUsize::new(recv_budget),
            recv_budget,
        })
    }

    pub(crate) fn take_released_recv_bytes(&self) -> usize {
        self.released_recv_bytes.swap(0, Ordering::Relaxed)
    }

    pub(crate) fn release_send_bytes(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        release_credit(&self.send_available, self.send_budget, bytes);
        self.send_notify.notify_waiters();
    }

    async fn reserve_send_bytes(&self, bytes: usize) -> Result<()> {
        let capped = bytes.min(self.send_budget);
        if capped == 0 {
            return Ok(());
        }
        loop {
            let notified = self.send_notify.notified();
            if reserve_credit(&self.send_available, capped) {
                return Ok(());
            }
            notified.await;
        }
    }

    pub(crate) fn try_reserve_inbound_bytes(&self, bytes: usize) -> bool {
        if bytes == 0 {
            return true;
        }
        let capped = bytes.min(self.recv_budget);
        reserve_credit(&self.recv_available, capped)
    }

    pub(crate) fn release_inbound_bytes(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        release_credit(&self.recv_available, self.recv_budget, bytes);
    }

    pub(crate) fn release_recv_data_bytes(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        self.release_inbound_bytes(bytes);
        self.released_recv_bytes
            .fetch_add(data_frame_encoded_len(bytes), Ordering::Relaxed);
        self.driver_notify.notify_one();
    }

    pub(crate) fn has_inbound_capacity(&self) -> bool {
        self.recv_available.load(Ordering::Relaxed) > 0
    }

    pub(crate) fn capacity(&self) -> H3TunnelCapacity {
        let outbound_available_bytes = self
            .send_available
            .load(Ordering::Relaxed)
            .min(self.send_budget);
        let inbound_available_bytes = self
            .recv_available
            .load(Ordering::Relaxed)
            .min(self.recv_budget);
        H3TunnelCapacity {
            outbound_budget: self.send_budget,
            outbound_available_bytes,
            outbound_pending_bytes: self.send_budget.saturating_sub(outbound_available_bytes),
            inbound_budget: self.recv_budget,
            inbound_available_bytes,
            inbound_pending_bytes: self.recv_budget.saturating_sub(inbound_available_bytes),
        }
    }

    #[cfg(test)]
    pub(crate) fn available_send_permits(&self) -> usize {
        self.send_available.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn available_inbound_permits(&self) -> usize {
        self.recv_available.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn reserve_send_permits_for_test(&self, bytes: usize) {
        assert!(reserve_credit(
            &self.send_available,
            bytes.min(self.send_budget)
        ));
    }
}

fn reserve_credit(available: &AtomicUsize, bytes: usize) -> bool {
    let mut current = available.load(Ordering::Acquire);
    loop {
        if current < bytes {
            return false;
        }
        match available.compare_exchange_weak(
            current,
            current - bytes,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(next) => current = next,
        }
    }
}

fn release_credit(available: &AtomicUsize, budget: usize, bytes: usize) {
    let capped = bytes.min(budget);
    if capped == 0 {
        return;
    }
    let _ = available.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        Some(current.saturating_add(capped).min(budget))
    });
}

#[derive(Debug)]
enum H3TunnelInboundReceiver {
    Bounded(mpsc::Receiver<Result<H3TunnelEvent>>),
    Unbounded(mpsc::UnboundedReceiver<Result<H3TunnelEvent>>),
}

impl H3TunnelInboundReceiver {
    async fn recv(&mut self) -> Option<Result<H3TunnelEvent>> {
        match self {
            Self::Bounded(rx) => rx.recv().await,
            Self::Unbounded(rx) => rx.recv().await,
        }
    }

    fn try_recv(
        &mut self,
    ) -> std::result::Result<Result<H3TunnelEvent>, mpsc::error::TryRecvError> {
        match self {
            Self::Bounded(rx) => rx.try_recv(),
            Self::Unbounded(rx) => rx.try_recv(),
        }
    }
}

/// Outbound sink for a tunnel handle. `Direct` posts a pre-tagged
/// `(stream_id, frame)` straight onto the driver's shared bounded outbound
/// channel, one task hop to the driver. `Unbounded` backs `H3Tunnel::new` and
/// the in-crate test fixtures that own the receiver themselves.
#[derive(Debug)]
enum H3TunnelOutboundSink {
    Unbounded(mpsc::UnboundedSender<H3TunnelOutbound>),
    Direct {
        stream_id: u64,
        tx: mpsc::Sender<(u64, H3TunnelOutbound)>,
    },
    OwnedDirect {
        stream_id: u64,
    },
}

struct H3OwnedTunnelDriver {
    driver: NativeH3Driver,
    slot: H3DirectDriverSlot,
    recv_buf: Vec<u8>,
}

// The owned direct driver is private state for the send_bytes_owned /
// recv_event_owned path. Those methods require &mut H3Tunnel, and the shared
// send_bytes(&self) API rejects OwnedDirect before touching this field.
// Keeping H3Tunnel: Sync preserves the public tunnel type's ability to be
// referenced from spawned tasks while still preventing shared access to the
// non-Sync native driver.
unsafe impl Sync for H3OwnedTunnelDriver {}

impl std::fmt::Debug for H3OwnedTunnelDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3OwnedTunnelDriver")
            .finish_non_exhaustive()
    }
}

/// Byte transport for an RFC 9220 WebSocket-over-HTTP/3 tunnel stream.
#[derive(Debug)]
pub struct H3Tunnel {
    outbound_tx: H3TunnelOutboundSink,
    inbound_rx: H3TunnelInboundReceiver,
    credit: Option<Arc<H3TunnelCredit>>,
    owned_driver: Option<H3OwnedTunnelDriver>,
    inline_inbound: Option<Arc<H3TunnelInlineInbound>>,
}

impl H3Tunnel {
    pub fn new(
        outbound_tx: mpsc::UnboundedSender<H3TunnelOutbound>,
        inbound_rx: mpsc::Receiver<Result<H3TunnelEvent>>,
    ) -> Self {
        Self {
            outbound_tx: H3TunnelOutboundSink::Unbounded(outbound_tx),
            inbound_rx: H3TunnelInboundReceiver::Bounded(inbound_rx),
            credit: None,
            owned_driver: None,
            inline_inbound: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_credit(
        outbound_tx: mpsc::UnboundedSender<H3TunnelOutbound>,
        inbound_rx: mpsc::UnboundedReceiver<Result<H3TunnelEvent>>,
        credit: Arc<H3TunnelCredit>,
    ) -> Self {
        Self {
            outbound_tx: H3TunnelOutboundSink::Unbounded(outbound_tx),
            inbound_rx: H3TunnelInboundReceiver::Unbounded(inbound_rx),
            credit: Some(credit),
            owned_driver: None,
            inline_inbound: None,
        }
    }

    /// Build a tunnel handle whose send path posts directly onto the driver's
    /// shared bounded outbound channel, pre-tagged with `stream_id`. This drops
    /// the per-tunnel relay task and one cross-worker wake per `send_bytes`.
    pub(crate) fn new_direct_with_credit(
        stream_id: u64,
        tunnel_outbound_tx: mpsc::Sender<(u64, H3TunnelOutbound)>,
        inbound_rx: mpsc::UnboundedReceiver<Result<H3TunnelEvent>>,
        credit: Arc<H3TunnelCredit>,
    ) -> Self {
        Self {
            outbound_tx: H3TunnelOutboundSink::Direct {
                stream_id,
                tx: tunnel_outbound_tx,
            },
            inbound_rx: H3TunnelInboundReceiver::Unbounded(inbound_rx),
            credit: Some(credit),
            owned_driver: None,
            inline_inbound: None,
        }
    }

    pub(crate) fn new_direct_with_credit_and_inline(
        stream_id: u64,
        tunnel_outbound_tx: mpsc::Sender<(u64, H3TunnelOutbound)>,
        inbound_rx: mpsc::UnboundedReceiver<Result<H3TunnelEvent>>,
        credit: Arc<H3TunnelCredit>,
        inline_inbound: Arc<H3TunnelInlineInbound>,
    ) -> Self {
        Self {
            outbound_tx: H3TunnelOutboundSink::Direct {
                stream_id,
                tx: tunnel_outbound_tx,
            },
            inbound_rx: H3TunnelInboundReceiver::Unbounded(inbound_rx),
            credit: Some(credit),
            owned_driver: None,
            inline_inbound: Some(inline_inbound),
        }
    }

    pub(crate) fn into_owned_direct(
        mut self,
        stream_id: u64,
        driver: NativeH3Driver,
        slot: H3DirectDriverSlot,
    ) -> Self {
        let recv_buf = vec![0u8; driver.direct_recv_buffer_len()];
        self.outbound_tx = H3TunnelOutboundSink::OwnedDirect { stream_id };
        self.owned_driver = Some(H3OwnedTunnelDriver {
            driver,
            slot,
            recv_buf,
        });
        self
    }

    pub async fn send_bytes(&self, bytes: Bytes, fin: bool) -> Result<()> {
        // close_send (and any zero-byte send) skips the byte-credit semaphore so
        // a fin can always be queued even when the budget is exhausted.
        if !bytes.is_empty() {
            if let Some(credit) = self.credit.as_ref() {
                credit.reserve_send_bytes(bytes.len()).await?;
            }
        }
        match &self.outbound_tx {
            H3TunnelOutboundSink::Unbounded(tx) => tx
                .send(H3TunnelOutbound { bytes, fin })
                .map_err(|_| Error::HttpProtocol("H3 tunnel outbound channel closed".into())),
            H3TunnelOutboundSink::Direct { stream_id, tx } => {
                let item = (*stream_id, H3TunnelOutbound { bytes, fin });
                match tx.try_send(item) {
                    Ok(()) => Ok(()),
                    Err(TrySendError::Full(item)) => tx.send(item).await.map_err(|_| {
                        Error::HttpProtocol("H3 tunnel outbound channel closed".into())
                    }),
                    Err(TrySendError::Closed(_)) => Err(Error::HttpProtocol(
                        "H3 tunnel outbound channel closed".into(),
                    )),
                }
            }
            H3TunnelOutboundSink::OwnedDirect { .. } => Err(Error::HttpProtocol(
                "owned direct H3 tunnel requires send_bytes_owned".into(),
            )),
        }
    }

    #[doc(hidden)]
    pub async fn send_bytes_owned(&mut self, bytes: Bytes, fin: bool) -> Result<()> {
        if !bytes.is_empty() {
            if let Some(credit) = self.credit.as_ref() {
                credit.reserve_send_bytes(bytes.len()).await?;
            }
        }
        let H3TunnelOutboundSink::OwnedDirect { stream_id } = &self.outbound_tx else {
            return self.send_bytes(bytes, fin).await;
        };
        let Some(owned) = self.owned_driver.as_mut() else {
            return Err(Error::HttpProtocol(
                "owned direct H3 tunnel driver is unavailable".into(),
            ));
        };
        owned
            .driver
            .send_direct_tunnel_outbound(*stream_id, H3TunnelOutbound { bytes, fin })
            .await
    }

    pub async fn close_send(&self) -> Result<()> {
        self.send_bytes(Bytes::new(), true).await
    }

    #[doc(hidden)]
    pub async fn close_send_owned(&mut self) -> Result<()> {
        self.send_bytes_owned(Bytes::new(), true).await
    }

    #[doc(hidden)]
    pub async fn round_trip_bytes_owned(&mut self, bytes: Bytes) -> Result<Bytes> {
        let expected = bytes.len();
        self.send_bytes_owned(bytes, false).await?;
        let mut echoed = Bytes::new();
        let mut received = 0usize;
        while received < expected {
            let chunk = self.recv_bytes().await.ok_or_else(|| {
                Error::HttpProtocol(format!(
                    "owned direct H3 tunnel closed after {received} of {expected} echoed bytes"
                ))
            })??;
            received = received.saturating_add(chunk.len());
            if echoed.is_empty() {
                echoed = chunk;
            } else {
                let mut combined = bytes::BytesMut::with_capacity(echoed.len() + chunk.len());
                combined.extend_from_slice(&echoed);
                combined.extend_from_slice(&chunk);
                echoed = combined.freeze();
            }
        }
        if received != expected {
            return Err(Error::HttpProtocol(format!(
                "owned direct H3 tunnel echo length mismatch: expected {expected}, got {received}"
            )));
        }
        Ok(echoed)
    }

    pub fn capacity(&self) -> H3TunnelCapacity {
        self.credit
            .as_ref()
            .map(|credit| credit.capacity())
            .unwrap_or_default()
    }

    pub async fn recv_event(&mut self) -> Option<Result<H3TunnelEvent>> {
        if matches!(self.outbound_tx, H3TunnelOutboundSink::OwnedDirect { .. }) {
            return self.recv_event_owned().await;
        }
        let event = self.inbound_rx.recv().await?;
        if let Ok(H3TunnelEvent::Data(bytes)) = &event {
            self.release_recv_bytes(bytes.len());
        } else if let Some(credit) = self.credit.as_ref() {
            credit.driver_notify.notify_one();
        }
        Some(event)
    }

    async fn recv_event_owned(&mut self) -> Option<Result<H3TunnelEvent>> {
        loop {
            if let Some(inline) = self.inline_inbound.as_ref() {
                if let Some(event) = inline.pop() {
                    if let Ok(H3TunnelEvent::Data(bytes)) = &event {
                        self.release_recv_bytes(bytes.len());
                    } else if let Some(credit) = self.credit.as_ref() {
                        credit.driver_notify.notify_one();
                    }
                    return Some(event);
                }
            }
            match self.inbound_rx.try_recv() {
                Ok(event) => {
                    if let Ok(H3TunnelEvent::Data(bytes)) = &event {
                        self.release_recv_bytes(bytes.len());
                    } else if let Some(credit) = self.credit.as_ref() {
                        credit.driver_notify.notify_one();
                    }
                    return Some(event);
                }
                Err(mpsc::error::TryRecvError::Disconnected) => return None,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
            let H3TunnelOutboundSink::OwnedDirect { stream_id: _ } = &self.outbound_tx else {
                return self.inbound_rx.recv().await;
            };
            let Some(owned) = self.owned_driver.as_mut() else {
                return Some(Err(Error::HttpProtocol(
                    "owned direct H3 tunnel driver is unavailable".into(),
                )));
            };
            if let Err(error) = owned
                .driver
                .drive_direct_tunnel_once_with_buf(&mut owned.recv_buf)
                .await
            {
                return Some(Err(error));
            }
        }
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
            credit.release_inbound_bytes(released);
            credit
                .released_recv_bytes
                .fetch_add(data_frame_encoded_len(released), Ordering::Relaxed);
        }
        credit.driver_notify.notify_one();
    }
}

impl Drop for H3Tunnel {
    fn drop(&mut self) {
        if let Some(owned) = self.owned_driver.take() {
            if owned.driver.is_direct_reusable() {
                owned.slot.put(owned.driver);
            } else {
                owned.slot.spawn(owned.driver);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex as TokioMutex;
    use tokio::time::{sleep, timeout};

    /// Drives the outbound side of a tunnel: drain the unbounded channel and
    /// hand each chunk to the driver-side credit-release callback under a
    /// configurable per-chunk delay. The release path mirrors what
    /// `flush_tunnel_data_once` does on the wire send path - it never returns
    /// more than `acquired_credit` worth of permits per outbound, so this is a
    /// faithful stand-in for the byte-bounded backpressure contract.
    struct OutboundDrainer {
        outbound_rx: TokioMutex<mpsc::UnboundedReceiver<H3TunnelOutbound>>,
        credit: Arc<H3TunnelCredit>,
        chunk_size: usize,
        per_chunk_delay: Duration,
        peak_in_flight: Arc<AtomicUsize>,
    }

    impl OutboundDrainer {
        fn new(
            outbound_rx: mpsc::UnboundedReceiver<H3TunnelOutbound>,
            credit: Arc<H3TunnelCredit>,
            chunk_size: usize,
            per_chunk_delay: Duration,
        ) -> Arc<Self> {
            Arc::new(Self {
                outbound_rx: TokioMutex::new(outbound_rx),
                credit,
                chunk_size,
                per_chunk_delay,
                peak_in_flight: Arc::new(AtomicUsize::new(0)),
            })
        }

        async fn run(self: Arc<Self>) -> Vec<H3TunnelOutbound> {
            let mut collected = Vec::new();
            let mut rx = self.outbound_rx.lock().await;
            while let Some(outbound) = rx.recv().await {
                let budget = self.credit.send_budget;
                let acquired = outbound.bytes.len().min(budget);

                // Observe peak in-flight as bytes that have been admitted past the
                // semaphore but not yet released back to it.
                let in_flight = budget - self.credit.available_send_permits();
                self.peak_in_flight
                    .fetch_max(in_flight, AtomicOrdering::SeqCst);

                let mut released = 0usize;
                let total = outbound.bytes.len();
                if total == 0 {
                    // close_send: no credit was acquired, nothing to release.
                    collected.push(outbound.clone());
                    if outbound.fin {
                        // signal the test that the producer is done
                        return collected;
                    }
                    continue;
                }
                let mut offset = 0usize;
                while offset < total {
                    let chunk = self.chunk_size.min(total - offset);
                    if !self.per_chunk_delay.is_zero() {
                        sleep(self.per_chunk_delay).await;
                    }
                    let release_now = chunk.min(acquired.saturating_sub(released));
                    if release_now > 0 {
                        self.credit.release_send_bytes(release_now);
                        released = released.saturating_add(release_now);
                    }
                    offset += chunk;
                }
                if released < acquired {
                    self.credit.release_send_bytes(acquired - released);
                }
                collected.push(outbound);
            }
            collected
        }
    }

    fn make_tunnel(
        budget: usize,
    ) -> (
        H3Tunnel,
        mpsc::UnboundedReceiver<H3TunnelOutbound>,
        Arc<H3TunnelCredit>,
    ) {
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<H3TunnelOutbound>();
        let (_inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Result<H3TunnelEvent>>();
        let credit = H3TunnelCredit::new(Arc::new(Notify::new()), budget, budget);
        let tunnel = H3Tunnel::new_with_credit(outbound_tx, inbound_rx, credit.clone());
        (tunnel, outbound_rx, credit)
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn send_larger_than_budget_blocks_until_consumer_drains() {
        let budget = 64 * 1024;
        let (tunnel, outbound_rx, credit) = make_tunnel(budget);

        // Prefill: drain every credit permit before the producer starts. This
        // guarantees the producer's first `send_bytes` must observe the
        // drainer releasing permits in order to proceed; otherwise the test
        // could not distinguish byte-bounded backpressure from a no-op
        // semaphore.
        credit.reserve_send_permits_for_test(budget);
        assert_eq!(credit.available_send_permits(), 0);

        // 4x budget single producer payload + a small follow-up so the test
        // also exercises the "oversized chunk waits, then a normal-sized chunk
        // succeeds once enough credit is back" path. The drainer releases
        // permits in small slices so producers genuinely contend for budget.
        let payload_size = 4 * budget;
        let payload = Bytes::from(vec![0x42u8; payload_size]);
        let follow_up = Bytes::from(vec![0x21u8; budget / 2]);

        let drainer = OutboundDrainer::new(
            outbound_rx,
            credit.clone(),
            budget / 8,
            Duration::from_millis(1),
        );
        let drainer_handle = {
            let drainer = drainer.clone();
            tokio::spawn(async move { drainer.run().await })
        };

        let tunnel = Arc::new(tunnel);
        let producer = {
            let tunnel = tunnel.clone();
            let payload = payload.clone();
            let follow_up = follow_up.clone();
            tokio::spawn(async move {
                tunnel
                    .send_bytes(payload, false)
                    .await
                    .expect("oversized send_bytes must complete once credit is released");
                tunnel
                    .send_bytes(follow_up, false)
                    .await
                    .expect("follow-up send_bytes must complete");
                tunnel
                    .send_bytes(Bytes::new(), true)
                    .await
                    .expect("close_send must complete even after credit is drained");
            })
        };

        // Release the prefilled credit so the producer can make initial
        // progress; from there the drainer keeps refunding credit as it
        // observes the producer's chunks.
        credit.release_send_bytes(budget);

        timeout(Duration::from_secs(5), producer)
            .await
            .expect("producer must not deadlock when sending more than budget")
            .expect("producer task panicked");

        let collected = drainer_handle.await.expect("drainer task did not panic");
        let total_collected: usize = collected.iter().map(|o| o.bytes.len()).sum();
        assert_eq!(
            total_collected,
            payload_size + follow_up.len(),
            "drainer must have observed every byte the producer queued"
        );
        assert!(
            collected.last().expect("at least one outbound").fin,
            "last drained outbound must carry the producer's close_send fin"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn two_producers_respect_total_byte_budget() {
        let budget = 8 * 1024;
        let (tunnel, outbound_rx, credit) = make_tunnel(budget);

        let drainer =
            OutboundDrainer::new(outbound_rx, credit.clone(), 512, Duration::from_millis(2));
        let peak_in_flight = drainer.peak_in_flight.clone();
        let drainer_handle = {
            let drainer = drainer.clone();
            tokio::spawn(async move { drainer.run().await })
        };

        // Two concurrent producers race for the same credit semaphore via
        // `tokio::join!`. Sharing `&tunnel` across two futures on the same
        // task is enough to exercise interleaving without requiring
        // `H3Tunnel: Sync` (mpsc::Receiver is `!Sync`).
        let tunnel_ref = &tunnel;
        let producer_a = async move {
            for _ in 0..6 {
                tunnel_ref
                    .send_bytes(Bytes::from(vec![1u8; 2 * 1024]), false)
                    .await
                    .expect("producer A send_bytes");
            }
        };
        let producer_b = async move {
            for _ in 0..6 {
                tunnel_ref
                    .send_bytes(Bytes::from(vec![2u8; 2 * 1024]), false)
                    .await
                    .expect("producer B send_bytes");
            }
        };
        tokio::join!(producer_a, producer_b);

        // Final fin so the drainer exits.
        tunnel
            .send_bytes(Bytes::new(), true)
            .await
            .expect("final fin send");
        drainer_handle.await.expect("drainer did not panic");

        let observed_peak = peak_in_flight.load(AtomicOrdering::SeqCst);
        assert!(
            observed_peak <= budget,
            "peak in-flight bytes {observed_peak} must not exceed the configured budget {budget}",
        );
        // Sanity check that the producers actually shared the pipe (otherwise
        // the bound above is uninteresting).
        assert!(
            observed_peak >= 2 * 1024,
            "peak in-flight should be at least one full producer chunk (was {observed_peak})",
        );
    }

    #[tokio::test(start_paused = false)]
    async fn close_send_works_when_budget_is_exhausted() {
        let budget = 4 * 1024;
        let (tunnel, mut outbound_rx, credit) = make_tunnel(budget);

        // Drain all permits without ever returning them so the budget is exhausted.
        credit.reserve_send_permits_for_test(budget);
        assert_eq!(credit.available_send_permits(), 0);

        // close_send is fin-only and must not block on the byte-credit semaphore.
        timeout(Duration::from_secs(2), tunnel.close_send())
            .await
            .expect("close_send must not block on the credit semaphore when budget is exhausted")
            .expect("close_send returned an error");

        let queued = outbound_rx
            .recv()
            .await
            .expect("close_send must enqueue an outbound with fin");
        assert!(queued.bytes.is_empty(), "close_send must send empty bytes");
        assert!(queued.fin, "close_send must mark the outbound as fin");
        // Nothing else should be in the queue.
        assert!(outbound_rx.try_recv().is_err());
    }

    #[test]
    fn release_send_bytes_is_capped_at_send_budget() {
        let budget = 16 * 1024;
        let credit = H3TunnelCredit::new(Arc::new(Notify::new()), budget, budget);
        // Drain everything.
        credit.reserve_send_permits_for_test(budget);
        assert_eq!(credit.available_send_permits(), 0);

        // Releasing 4x the budget must not push the semaphore above its
        // configured ceiling; otherwise the per-tunnel cap would lose meaning.
        credit.release_send_bytes(4 * budget);
        assert_eq!(credit.available_send_permits(), budget);
    }

    #[test]
    fn capacity_snapshot_reports_tunnel_backpressure_budgets() {
        let budget = 16 * 1024;
        let (tunnel, _outbound_rx, credit) = make_tunnel(budget);
        credit.reserve_send_permits_for_test(4 * 1024);
        assert!(credit.try_reserve_inbound_bytes(2 * 1024));

        let capacity = tunnel.capacity();

        assert_eq!(capacity.outbound_budget, budget);
        assert_eq!(capacity.outbound_available_bytes, 12 * 1024);
        assert_eq!(capacity.outbound_pending_bytes, 4 * 1024);
        assert_eq!(capacity.inbound_budget, budget);
        assert_eq!(capacity.inbound_available_bytes, 14 * 1024);
        assert_eq!(capacity.inbound_pending_bytes, 2 * 1024);
    }

    #[tokio::test]
    async fn recv_event_releases_encoded_data_frame_credit() {
        let (_outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        drop(outbound_rx);
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let credit = H3TunnelCredit::new(Arc::new(Notify::new()), 1024, 1024);
        let mut tunnel = H3Tunnel::new_with_credit(_outbound_tx, inbound_rx, credit.clone());
        assert!(credit.try_reserve_inbound_bytes(64));

        inbound_tx
            .send(Ok(H3TunnelEvent::Data(Bytes::from(vec![0x42; 64]))))
            .expect("queue inbound data");

        let event = tunnel.recv_event().await.expect("inbound event");
        assert!(matches!(event, Ok(H3TunnelEvent::Data(bytes)) if bytes.len() == 64));
        assert_eq!(
            credit.take_released_recv_bytes(),
            67,
            "64 payload bytes must release DATA frame type + two-byte length overhead"
        );
        assert_eq!(credit.available_inbound_permits(), 1024);
    }
}
