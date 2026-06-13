//! Poll-based HTTP/3 response body delivery.

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::{sleep, Sleep};

use crate::error::Error;
use crate::transport::h3::native::data_frame_encoded_len;

#[derive(Clone, Copy, Debug, Default)]
pub struct H3BodyTimeouts {
    pub(crate) read_idle: Option<Duration>,
    pub(crate) total: Option<Duration>,
}

#[derive(Debug)]
pub(crate) enum H3BodyDataPush {
    Accepted,
    Full(Bytes),
    Closed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct H3BodyDrain {
    pub accepted: usize,
    pub finished: bool,
    pub closed: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct H3BodyCapacity {
    pub buffer_capacity: usize,
    pub buffered_chunks: usize,
    pub available_slots: usize,
    pub buffered_bytes: usize,
    pub closed: bool,
    pub ended: bool,
}

/// Default bounded in-flight DATA item capacity per H3 stream body.
pub(crate) const DEFAULT_H3_BODY_SLOT_CAPACITY: usize = 64;

struct H3BodyState {
    slots: VecDeque<std::result::Result<Bytes, Error>>,
    cap: usize,
    buffered_bytes: usize,
    terminal_error: Option<Error>,
    ended: bool,
    closed: bool,
    consumer_waker: Option<Waker>,
}

impl Default for H3BodyState {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_H3_BODY_SLOT_CAPACITY)
    }
}

impl H3BodyState {
    fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            slots: VecDeque::with_capacity(capacity),
            cap: capacity,
            buffered_bytes: 0,
            terminal_error: None,
            ended: false,
            closed: false,
            consumer_waker: None,
        }
    }
}

/// Shared DATA slots between the H3 driver and the public `Body` poller.
///
/// Bounded `VecDeque` plus consumer `Waker` and driver `Notify`. The cap is a
/// safety bound on in-flight chunks; QUIC stream-level flow control still
/// bounds total in-flight bytes.
pub struct H3BodyShared {
    state: Mutex<H3BodyState>,
    released_recv_bytes: AtomicUsize,
    driver_notify: Arc<Notify>,
}

impl fmt::Debug for H3BodyShared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().expect("h3 body state poisoned");
        f.debug_struct("H3BodyShared")
            .field("slot_count", &state.slots.len())
            .field("cap", &state.cap)
            .field("ended", &state.ended)
            .field("closed", &state.closed)
            .finish()
    }
}

impl H3BodyShared {
    pub(crate) fn new_with_capacity(driver_notify: Arc<Notify>, capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(H3BodyState::with_capacity(capacity)),
            released_recv_bytes: AtomicUsize::new(0),
            driver_notify,
        })
    }

    pub(crate) fn push_data(&self, bytes: Bytes) -> H3BodyDataPush {
        let mut state = self.state.lock().expect("h3 body state poisoned");
        if state.closed {
            return H3BodyDataPush::Closed;
        }
        if state.slots.len() >= state.cap {
            return H3BodyDataPush::Full(bytes);
        }
        state.buffered_bytes = state.buffered_bytes.saturating_add(bytes.len());
        state.slots.push_back(Ok(bytes));
        if let Some(waker) = state.consumer_waker.take() {
            waker.wake();
        }
        H3BodyDataPush::Accepted
    }

    pub(crate) fn push_pending_data(
        &self,
        pending: &mut VecDeque<Bytes>,
        finish_when_drained: bool,
    ) -> H3BodyDrain {
        let mut state = self.state.lock().expect("h3 body state poisoned");
        if state.closed {
            return H3BodyDrain {
                closed: true,
                ..H3BodyDrain::default()
            };
        }

        let mut drain = H3BodyDrain::default();
        while state.slots.len() < state.cap {
            let Some(bytes) = pending.pop_front() else {
                break;
            };
            state.buffered_bytes = state.buffered_bytes.saturating_add(bytes.len());
            state.slots.push_back(Ok(bytes));
            drain.accepted += 1;
        }

        if finish_when_drained && pending.is_empty() && !state.ended {
            state.ended = true;
            drain.finished = true;
        }

        if drain.accepted > 0 || drain.finished {
            if let Some(waker) = state.consumer_waker.take() {
                waker.wake();
            }
        }

        drain
    }

    pub(crate) fn fail(&self, error: Error) {
        let mut state = self.state.lock().expect("h3 body state poisoned");
        if state.closed {
            return;
        }
        if state.slots.len() >= state.cap {
            if state.terminal_error.is_none() {
                state.terminal_error = Some(error);
                if let Some(waker) = state.consumer_waker.take() {
                    waker.wake();
                }
            }
            return;
        }
        state.slots.push_back(Err(error));
        if let Some(waker) = state.consumer_waker.take() {
            waker.wake();
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state.lock().expect("h3 body state poisoned").closed
    }

    pub(crate) fn is_slot_available(&self) -> bool {
        let state = self.state.lock().expect("h3 body state poisoned");
        !state.closed && state.slots.len() < state.cap
    }

    pub(crate) fn take_released_recv_bytes(&self) -> usize {
        self.released_recv_bytes.swap(0, Ordering::Relaxed)
    }

    pub(crate) fn drain_ready_items_for_direct(
        &self,
    ) -> VecDeque<std::result::Result<Bytes, Error>> {
        let mut state = self.state.lock().expect("h3 body state poisoned");
        let mut drained = VecDeque::with_capacity(state.slots.len());
        while let Some(item) = state.slots.pop_front() {
            if let Ok(bytes) = &item {
                state.buffered_bytes = state.buffered_bytes.saturating_sub(bytes.len());
            }
            drained.push_back(item);
        }
        drained
    }

    pub(crate) fn release_direct_item_bytes(&self, len: usize) {
        self.released_recv_bytes
            .fetch_add(data_frame_encoded_len(len), Ordering::Relaxed);
        self.driver_notify.notify_one();
    }

    pub(crate) fn capacity(&self) -> H3BodyCapacity {
        let state = self.state.lock().expect("h3 body state poisoned");
        H3BodyCapacity {
            buffer_capacity: state.cap,
            buffered_chunks: state.slots.len(),
            available_slots: state.cap.saturating_sub(state.slots.len()),
            buffered_bytes: state.buffered_bytes,
            closed: state.closed,
            ended: state.ended,
        }
    }

    fn close(&self) {
        let mut state = self.state.lock().expect("h3 body state poisoned");
        if !state.closed {
            state.closed = true;
            if let Some(waker) = state.consumer_waker.take() {
                waker.wake();
            }
            self.driver_notify.notify_one();
        }
    }
}

/// HTTP/3 response body backed by driver-owned wakeable state.
pub(crate) struct H3Body {
    shared: Arc<H3BodyShared>,
    read_idle_timeout: Option<Duration>,
    read_idle_sleep: Option<Pin<Box<Sleep>>>,
    total_timeout: Option<Duration>,
    total_sleep: Option<Pin<Box<Sleep>>>,
    terminal: bool,
}

impl H3Body {
    pub(crate) fn new(shared: Arc<H3BodyShared>, timeouts: H3BodyTimeouts) -> Self {
        Self {
            shared,
            read_idle_timeout: timeouts.read_idle,
            read_idle_sleep: timeouts.read_idle.map(|duration| Box::pin(sleep(duration))),
            total_timeout: timeouts.total,
            total_sleep: timeouts.total.map(|duration| Box::pin(sleep(duration))),
            terminal: false,
        }
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.terminal
    }

    pub(crate) fn capacity(&self) -> H3BodyCapacity {
        self.shared.capacity()
    }

    pub(crate) fn drain_ready_items_for_direct(
        &mut self,
    ) -> VecDeque<std::result::Result<Bytes, Error>> {
        self.shared.drain_ready_items_for_direct()
    }

    pub(crate) fn record_direct_item_consumed(&mut self, len: usize) {
        self.shared.release_direct_item_bytes(len);
        self.reset_read_idle();
    }

    fn reset_read_idle(&mut self) {
        if let Some(duration) = self.read_idle_timeout {
            self.read_idle_sleep = Some(Box::pin(sleep(duration)));
        }
    }
}

impl Drop for H3Body {
    fn drop(&mut self) {
        if !self.terminal {
            self.shared.close();
        }
    }
}

impl H3Body {
    pub(crate) fn poll_data(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Bytes, Error>>> {
        if self.terminal {
            return Poll::Ready(None);
        }

        enum StatePoll {
            Item(std::result::Result<Bytes, Error>),
            Error(Error),
            End,
            Pending,
        }

        let state_poll = {
            let mut state = self.shared.state.lock().expect("h3 body state poisoned");
            if let Some(item) = state.slots.pop_front() {
                if let Ok(bytes) = &item {
                    state.buffered_bytes = state.buffered_bytes.saturating_sub(bytes.len());
                }
                StatePoll::Item(item)
            } else if let Some(error) = state.terminal_error.take() {
                state.closed = true;
                StatePoll::Error(error)
            } else if state.ended {
                state.closed = true;
                StatePoll::End
            } else {
                state.consumer_waker = Some(cx.waker().clone());
                self.shared.driver_notify.notify_one();
                StatePoll::Pending
            }
        };

        match state_poll {
            StatePoll::Error(error) => {
                self.terminal = true;
                return Poll::Ready(Some(Err(error)));
            }
            StatePoll::End => {
                self.terminal = true;
                self.shared.driver_notify.notify_one();
                return Poll::Ready(None);
            }
            StatePoll::Pending => {}
            StatePoll::Item(item) => match item {
                Ok(bytes) => {
                    self.shared
                        .released_recv_bytes
                        .fetch_add(data_frame_encoded_len(bytes.len()), Ordering::Relaxed);
                    self.shared.driver_notify.notify_one();
                    self.reset_read_idle();
                    if bytes.is_empty() {
                        return self.poll_data(cx);
                    }
                    return Poll::Ready(Some(Ok(bytes)));
                }
                Err(error) => {
                    self.terminal = true;
                    self.shared.close();
                    return Poll::Ready(Some(Err(error)));
                }
            },
        }

        if let Some(total_sleep) = self.total_sleep.as_mut() {
            if total_sleep.as_mut().poll(cx).is_ready() {
                let duration = self.total_timeout.expect("total sleep without duration");
                self.terminal = true;
                self.shared.close();
                return Poll::Ready(Some(Err(Error::TotalTimeout(duration))));
            }
        }

        if let Some(read_idle_sleep) = self.read_idle_sleep.as_mut() {
            if read_idle_sleep.as_mut().poll(cx).is_ready() {
                let duration = self
                    .read_idle_timeout
                    .expect("read-idle sleep without duration");
                self.terminal = true;
                self.shared.close();
                return Poll::Ready(Some(Err(Error::ReadIdleTimeout(duration))));
            }
        }

        Poll::Pending
    }
}

impl HttpBody for H3Body {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        match self.poll_data(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.terminal
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h3_body_shared_uses_configured_slot_capacity() {
        let shared = H3BodyShared::new_with_capacity(Arc::new(Notify::new()), 2);

        assert!(matches!(
            shared.push_data(Bytes::from_static(b"one")),
            H3BodyDataPush::Accepted
        ));
        assert!(matches!(
            shared.push_data(Bytes::from_static(b"two")),
            H3BodyDataPush::Accepted
        ));
        assert!(matches!(
            shared.push_data(Bytes::from_static(b"three")),
            H3BodyDataPush::Full(_)
        ));
    }

    #[test]
    fn h3_body_capacity_snapshot_reports_buffer_pressure() {
        let shared = H3BodyShared::new_with_capacity(Arc::new(Notify::new()), 3);
        assert!(matches!(
            shared.push_data(Bytes::from_static(b"one")),
            H3BodyDataPush::Accepted
        ));
        assert!(matches!(
            shared.push_data(Bytes::from_static(b"two-two")),
            H3BodyDataPush::Accepted
        ));

        let body = H3Body::new(shared.clone(), H3BodyTimeouts::default());
        let capacity = body.capacity();

        assert_eq!(capacity.buffer_capacity, 3);
        assert_eq!(capacity.buffered_chunks, 2);
        assert_eq!(capacity.available_slots, 1);
        assert_eq!(capacity.buffered_bytes, 10);
        assert!(!capacity.closed);
        assert!(!capacity.ended);
    }

    #[test]
    fn h3_body_reports_released_recv_bytes_when_consumer_takes_data() {
        struct NoopWake;

        impl std::task::Wake for NoopWake {
            fn wake(self: Arc<Self>) {}
        }

        let shared = H3BodyShared::new_with_capacity(Arc::new(Notify::new()), 2);
        assert!(matches!(
            shared.push_data(Bytes::from(vec![0x41; 63])),
            H3BodyDataPush::Accepted
        ));
        assert!(matches!(
            shared.push_data(Bytes::from(vec![0x42; 64])),
            H3BodyDataPush::Accepted
        ));

        let mut body = H3Body::new(shared.clone(), H3BodyTimeouts::default());
        let waker = std::task::Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);

        assert_eq!(shared.take_released_recv_bytes(), 0);
        let frame = Pin::new(&mut body).poll_frame(&mut context);
        assert!(matches!(frame, Poll::Ready(Some(Ok(_)))));
        assert_eq!(
            shared.take_released_recv_bytes(),
            65,
            "63 payload bytes must release DATA frame type + one-byte length overhead"
        );
        let frame = Pin::new(&mut body).poll_frame(&mut context);
        assert!(matches!(frame, Poll::Ready(Some(Ok(_)))));
        assert_eq!(
            shared.take_released_recv_bytes(),
            67,
            "64 payload bytes must release DATA frame type + two-byte length overhead"
        );
        assert_eq!(shared.take_released_recv_bytes(), 0);
    }
}
