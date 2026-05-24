//! Poll-based HTTP/2 response body delivery.

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::{sleep, Sleep};

use crate::error::Error;

#[derive(Clone, Copy, Debug, Default)]
pub struct H2BodyTimeouts {
    pub(crate) read_idle: Option<Duration>,
    pub(crate) total: Option<Duration>,
}

pub(crate) enum H2BodyPush {
    Accepted,
    Full(std::result::Result<Bytes, Error>),
    Closed,
}

/// Bounded in-flight DATA item capacity per H2 stream body.
///
/// H2 stream-level flow control still bounds total in-flight bytes; this cap
/// is a safety bound on the number of distinct chunks queued between the
/// driver and the consumer, which removes the per-chunk lock-step round-trip
/// the original single-slot design imposed.
const H2_BODY_SLOT_CAPACITY: usize = 32;
const MIN_RELEASE_NOTIFY_BYTES: usize = 8 * 1024;
const MAX_RELEASE_NOTIFY_BYTES: usize = 512 * 1024;

struct H2BodyState {
    slots: VecDeque<std::result::Result<Bytes, Error>>,
    cap: usize,
    terminal_error: Option<Error>,
    ended: bool,
    closed: bool,
    consumer_waker: Option<Waker>,
}

impl Default for H2BodyState {
    fn default() -> Self {
        Self {
            slots: VecDeque::with_capacity(H2_BODY_SLOT_CAPACITY),
            cap: H2_BODY_SLOT_CAPACITY,
            terminal_error: None,
            ended: false,
            closed: false,
            consumer_waker: None,
        }
    }
}

/// Shared DATA slots between the H2 driver and the public `Body` poller.
///
/// Driver-owned wakeable state with a bounded `VecDeque` of in-flight chunks
/// plus a consumer `Waker` and a `Notify` to wake the driver when the
/// consumer drains a chunk and the slot becomes refillable.
pub struct H2BodyShared {
    state: Mutex<H2BodyState>,
    closed: AtomicBool,
    released_recv_bytes: AtomicUsize,
    release_notify_bytes: usize,
    driver_notify: Arc<Notify>,
}

impl H2BodyShared {
    pub(crate) fn new(driver_notify: Arc<Notify>, initial_window_size: u32) -> Arc<Self> {
        let release_notify_bytes = ((initial_window_size as usize) / 4)
            .clamp(MIN_RELEASE_NOTIFY_BYTES, MAX_RELEASE_NOTIFY_BYTES);
        Arc::new(Self {
            state: Mutex::new(H2BodyState::default()),
            closed: AtomicBool::new(false),
            released_recv_bytes: AtomicUsize::new(0),
            release_notify_bytes,
            driver_notify,
        })
    }

    pub(crate) fn push(&self, item: std::result::Result<Bytes, Error>) -> H2BodyPush {
        if self.closed.load(Ordering::Acquire) {
            return H2BodyPush::Closed;
        }
        let mut state = self.state.lock().expect("h2 body state poisoned");
        if state.closed {
            return H2BodyPush::Closed;
        }
        if state.slots.len() >= state.cap {
            return H2BodyPush::Full(item);
        }
        let should_wake = state.slots.is_empty();
        state.slots.push_back(item);
        if should_wake {
            if let Some(waker) = state.consumer_waker.as_ref() {
                waker.wake_by_ref();
            }
        }
        H2BodyPush::Accepted
    }

    pub(crate) fn finish(&self) {
        let mut state = self.state.lock().expect("h2 body state poisoned");
        state.ended = true;
        if state.slots.is_empty() {
            if let Some(waker) = state.consumer_waker.as_ref() {
                waker.wake_by_ref();
            }
        }
    }

    pub(crate) fn fail(&self, error: Error) -> H2BodyPush {
        if self.closed.load(Ordering::Acquire) {
            return H2BodyPush::Closed;
        }
        let mut state = self.state.lock().expect("h2 body state poisoned");
        if state.closed {
            return H2BodyPush::Closed;
        }
        if state.slots.len() >= state.cap {
            return H2BodyPush::Full(Err(error));
        }
        let should_wake = state.slots.is_empty();
        state.slots.push_back(Err(error));
        if should_wake {
            if let Some(waker) = state.consumer_waker.as_ref() {
                waker.wake_by_ref();
            }
        }
        H2BodyPush::Accepted
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub(crate) fn is_slot_available(&self) -> bool {
        let state = self.state.lock().expect("h2 body state poisoned");
        !state.closed && state.slots.len() < state.cap
    }

    pub(crate) fn take_released_recv_bytes(&self) -> usize {
        self.released_recv_bytes.swap(0, Ordering::AcqRel)
    }

    pub(crate) fn has_released_recv_bytes(&self) -> bool {
        self.released_recv_bytes.load(Ordering::Acquire) > 0
    }

    fn close(&self) {
        let mut state = self.state.lock().expect("h2 body state poisoned");
        if !state.closed {
            state.closed = true;
            self.closed.store(true, Ordering::Release);
            if let Some(waker) = state.consumer_waker.take() {
                waker.wake();
            }
            self.driver_notify.notify_one();
        }
    }
}

/// HTTP/2 response body backed by driver-owned wakeable state.
pub(crate) struct H2Body {
    shared: Arc<H2BodyShared>,
    read_idle_timeout: Option<Duration>,
    read_idle_sleep: Option<Pin<Box<Sleep>>>,
    total_timeout: Option<Duration>,
    total_sleep: Option<Pin<Box<Sleep>>>,
    terminal: bool,
}

impl H2Body {
    pub(crate) fn new(shared: Arc<H2BodyShared>, timeouts: H2BodyTimeouts) -> Self {
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

    fn reset_read_idle(&mut self) {
        if let Some(duration) = self.read_idle_timeout {
            self.read_idle_sleep = Some(Box::pin(sleep(duration)));
        }
    }

    fn close_with_error(
        &mut self,
        error: Error,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Error>>> {
        self.terminal = true;
        self.shared.close();
        Poll::Ready(Some(Err(error)))
    }
}

impl Drop for H2Body {
    fn drop(&mut self) {
        if !self.terminal {
            self.shared.close();
        }
    }
}

impl HttpBody for H2Body {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        if self.terminal {
            return Poll::Ready(None);
        }

        enum StatePoll {
            Item {
                item: std::result::Result<Bytes, Error>,
                notify_slot_available: bool,
            },
            Error(Error),
            End,
            Pending,
        }

        let state_poll = {
            let mut state = self.shared.state.lock().expect("h2 body state poisoned");
            if let Some(item) = state.slots.pop_front() {
                StatePoll::Item {
                    item,
                    notify_slot_available: state.slots.len() + 1 >= state.cap,
                }
            } else if let Some(error) = state.terminal_error.take() {
                state.closed = true;
                StatePoll::Error(error)
            } else if state.ended {
                state.closed = true;
                StatePoll::End
            } else {
                let replace_waker = state
                    .consumer_waker
                    .as_ref()
                    .is_none_or(|waker| !waker.will_wake(cx.waker()));
                if replace_waker {
                    state.consumer_waker = Some(cx.waker().clone());
                }
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
                return Poll::Ready(None);
            }
            StatePoll::Pending => {}
            StatePoll::Item {
                item,
                notify_slot_available,
            } => match item {
                Ok(bytes) => {
                    let released = bytes.len();
                    let previous_released = self
                        .shared
                        .released_recv_bytes
                        .fetch_add(released, Ordering::AcqRel);
                    if notify_slot_available
                        || previous_released + released >= self.shared.release_notify_bytes
                    {
                        self.shared.driver_notify.notify_one();
                    }
                    self.reset_read_idle();
                    if bytes.is_empty() {
                        return self.poll_frame(cx);
                    }
                    return Poll::Ready(Some(Ok(Frame::data(bytes))));
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
                return self.close_with_error(Error::TotalTimeout(duration));
            }
        }

        if let Some(read_idle_sleep) = self.read_idle_sleep.as_mut() {
            if read_idle_sleep.as_mut().poll(cx).is_ready() {
                let duration = self
                    .read_idle_timeout
                    .expect("read-idle sleep without duration");
                return self.close_with_error(Error::ReadIdleTimeout(duration));
            }
        }

        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        self.terminal
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}
