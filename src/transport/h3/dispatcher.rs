//! Origin-fair admission for `H3Client` slow-path dispatch.
//!
//! Fast paths (the same-URL hot handle cache and the live-handle pool
//! lookup) are unchanged; only the slow path that ends up establishing a
//! fresh native H3 connection passes through this dispatcher. When several
//! slow-path requests are competing for admission, the dispatcher pops
//! waiters from a pool-level `OriginFairQueue` so siblings on a different
//! origin get a turn before the same origin is reused twice in a row.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::sync::oneshot;

use crate::pool::multiplexer::{OriginFairQueue, OriginKey};

struct H3DispatchEntry {
    waker: Option<oneshot::Sender<()>>,
}

#[derive(Default)]
struct H3DispatcherInner {
    queue: OriginFairQueue<H3DispatchEntry>,
    active: bool,
}

#[derive(Default)]
pub struct H3Dispatcher {
    inner: Mutex<H3DispatcherInner>,
}

impl std::fmt::Debug for H3Dispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock().expect("h3 dispatcher mutex");
        f.debug_struct("H3Dispatcher")
            .field("queued", &inner.queue.len())
            .field("active", &inner.active)
            .finish()
    }
}

impl H3Dispatcher {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(H3DispatcherInner::default()),
        })
    }

    /// Synchronously register a slow-path admission request and return a
    /// future that resolves when the dispatcher gives the caller the
    /// admission ticket.
    pub fn submit(self: &Arc<Self>, origin: OriginKey) -> H3DispatchSubmit {
        let (tx, rx) = oneshot::channel();
        {
            let mut inner = self.inner.lock().expect("h3 dispatcher mutex");
            if !inner.active {
                inner.active = true;
                let _ = tx.send(());
            } else {
                inner
                    .queue
                    .push_with_origin(origin, H3DispatchEntry { waker: Some(tx) });
            }
        }
        H3DispatchSubmit {
            dispatcher: Arc::clone(self),
            rx,
            consumed: false,
        }
    }

    /// Awaitable variant of [`submit`].
    pub async fn acquire(self: &Arc<Self>, origin: OriginKey) -> H3DispatchTicket {
        self.submit(origin).await
    }

    fn release(&self) {
        let mut inner = self.inner.lock().expect("h3 dispatcher mutex");
        loop {
            let Some(mut entry) = inner.queue.pop_next() else {
                inner.active = false;
                return;
            };
            if let Some(waker) = entry.waker.take() {
                if waker.send(()).is_ok() {
                    return;
                }
            }
        }
    }
}

/// Pending admission registration. Polling resolves once the dispatcher
/// has popped the registration in origin-fair order.
pub struct H3DispatchSubmit {
    dispatcher: Arc<H3Dispatcher>,
    rx: oneshot::Receiver<()>,
    consumed: bool,
}

impl Future for H3DispatchSubmit {
    type Output = H3DispatchTicket;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(_) => {
                self.consumed = true;
                Poll::Ready(H3DispatchTicket {
                    dispatcher: self.dispatcher.clone(),
                })
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for H3DispatchSubmit {
    fn drop(&mut self) {
        if self.consumed {
            return;
        }
        if let Ok(()) = self.rx.try_recv() {
            self.dispatcher.release();
        }
    }
}

/// Active admission ticket. The next waiter in origin-fair order is
/// signaled when the ticket is dropped.
pub struct H3DispatchTicket {
    dispatcher: Arc<H3Dispatcher>,
}

impl Drop for H3DispatchTicket {
    fn drop(&mut self) {
        self.dispatcher.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn origin(host: &str) -> OriginKey {
        OriginKey {
            host: host.to_string(),
            port: 443,
            is_https: true,
        }
    }

    #[tokio::test]
    async fn h3_dispatcher_rotates_ready_origins_before_same_origin_reuse() {
        let dispatcher = H3Dispatcher::new();
        let alpha = origin("alpha.example");
        let beta = origin("beta.example");

        let blocker = dispatcher.submit(alpha.clone()).await;

        let alpha2 = dispatcher.submit(alpha.clone());
        let alpha3 = dispatcher.submit(alpha.clone());
        let beta_submit = dispatcher.submit(beta.clone());

        let order = Arc::new(tokio::sync::Mutex::new(Vec::<&'static str>::new()));

        let order_a2 = order.clone();
        let t_a2 = tokio::spawn(async move {
            let _ticket = alpha2.await;
            order_a2.lock().await.push("alpha2");
        });
        let order_a3 = order.clone();
        let t_a3 = tokio::spawn(async move {
            let _ticket = alpha3.await;
            order_a3.lock().await.push("alpha3");
        });
        let order_b = order.clone();
        let t_b = tokio::spawn(async move {
            let _ticket = beta_submit.await;
            order_b.lock().await.push("beta");
        });

        drop(blocker);

        tokio::time::timeout(Duration::from_secs(2), async {
            t_a2.await.expect("alpha2 task");
            t_a3.await.expect("alpha3 task");
            t_b.await.expect("beta task");
        })
        .await
        .expect("dispatcher drained all waiters within bound");

        let recorded = order.lock().await.clone();
        assert_eq!(
            recorded,
            vec!["alpha2", "beta", "alpha3"],
            "H3 dispatcher must rotate alpha and beta before reusing alpha twice in a row"
        );
    }

    #[tokio::test]
    async fn h3_dispatcher_admits_single_origin_without_queue() {
        let dispatcher = H3Dispatcher::new();
        let alpha = origin("alpha.example");

        let first = dispatcher.submit(alpha.clone()).await;
        drop(first);
        let second = dispatcher.submit(alpha.clone()).await;
        drop(second);

        let inner = dispatcher.inner.lock().expect("h3 dispatcher mutex");
        assert!(
            inner.queue.is_empty() && !inner.active,
            "single-origin slow path must not leave state in the dispatcher after release"
        );
    }

    #[tokio::test]
    async fn h3_dispatcher_skips_dropped_submissions() {
        let dispatcher = H3Dispatcher::new();
        let alpha = origin("alpha.example");
        let beta = origin("beta.example");

        let blocker = dispatcher.submit(alpha.clone()).await;

        let dropped = dispatcher.submit(alpha.clone());
        let kept = dispatcher.submit(beta.clone());

        drop(dropped);
        drop(blocker);

        let ticket = tokio::time::timeout(Duration::from_secs(2), kept)
            .await
            .expect("kept submission must be signaled");
        drop(ticket);
    }
}
