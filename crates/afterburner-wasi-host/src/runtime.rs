//! Runs the host's futures on nuclei. Embedders of this crate may call it from
//! synchronous Rust and not use nuclei directly: [`in_runtime`] drives a future
//! to its end on the calling thread (the synchronous shims of the component
//! `Host` traits are written in terms of the async ones through it), on the
//! process default runtime or the runtime the calling thread is inside.
//!
//! This module also wraps nuclei's tasks. [`AbortOnDropJoinHandle`] is a
//! [`nuclei::Task`] that is named for what it does: this crate, and any child
//! crates which spawn tasks as part of their implementations, should use this
//! module's [`spawn`] and [`spawn_blocking`].

use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::task::{Context, Poll, Waker};

/// A [`nuclei::Task`] tied to the lifetime of its owner: dropping the handle
/// cancels the task.
///
/// This makes it easier to tie a worker task to the lifetime of a Resource
/// by keeping this handle owned by the Resource.
#[derive(Debug)]
pub struct AbortOnDropJoinHandle<T>(nuclei::Task<T>);
impl<T> AbortOnDropJoinHandle<T> {
    /// Abort the task and wait for it to finish. Optionally returns the result
    /// of the task if it ran to completion prior to being aborted.
    pub async fn cancel(self) -> Option<T> {
        self.0.cancel().await
    }
}
impl<T> std::ops::Deref for AbortOnDropJoinHandle<T> {
    type Target = nuclei::Task<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T> std::ops::DerefMut for AbortOnDropJoinHandle<T> {
    fn deref_mut(&mut self) -> &mut nuclei::Task<T> {
        &mut self.0
    }
}
impl<T> From<nuclei::Task<T>> for AbortOnDropJoinHandle<T> {
    fn from(task: nuclei::Task<T>) -> Self {
        AbortOnDropJoinHandle(task)
    }
}
impl<T> Future for AbortOnDropJoinHandle<T> {
    type Output = T;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

/// Spawns `f` on nuclei; the task is cancelled when the handle is dropped.
pub fn spawn<F>(f: F) -> AbortOnDropJoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    AbortOnDropJoinHandle(nuclei::spawn(f))
}

/// Runs `f` on nuclei's blocking pool; the handle cancels the job if it has
/// not started when the handle is dropped.
pub fn spawn_blocking<F, R>(f: F) -> AbortOnDropJoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    AbortOnDropJoinHandle(nuclei::spawn_blocking(f))
}

/// Drives `f` to its end on the calling thread. Called from a task, the call
/// nests: the thread's shard keeps running its other tasks and IO meanwhile.
pub fn in_runtime<F: Future>(f: F) -> F::Output {
    // The first `yield_now` lets the shard run its queue and poll its IO once
    // before `f`: a future that is always ready would otherwise never let the
    // background work that makes the next operation ready run, and a guest
    // that loops on "wait for readiness" then performs the operation would
    // spin forever (seen with UDP sockets in synchronous mode).
    nuclei::block_on(async move {
        nuclei::task::yield_now().await;
        f.await
    })
}

/// Invokes `f` with a noop waker, intended to be used in a `poll*`-style
/// function, and then returns whether the operation was ready or not.
///
/// This uses a "noop waker" to perform the poll and additionally handles
/// details such as opting-out of nuclei's cooperative task budget.
pub(crate) fn poll_now<T>(f: impl FnOnce(&mut Context<'_>) -> Poll<T>) -> Option<T> {
    let mut f = Some(f);
    // The budget is opted out of: this is the primitive for a number of wasip2
    // operations where the true blocking operation, `poll`, happens at some
    // future time in the guest's event loop, and an exhausted budget would
    // answer Pending at seemingly arbitrary points of that loop.
    let fut = pin!(nuclei::task::coop::unconstrained(poll_fn(move |cx| {
        match f.take() {
            Some(f) => f(cx),
            None => Poll::Pending,
        }
    })));

    let mut context = Context::from_waker(Waker::noop());
    match fut.poll(&mut context) {
        Poll::Ready(result) => Some(result),
        Poll::Pending => None,
    }
}

/// Attempts to get the result of a `future`.
///
/// This function does not block and will poll the provided future once. If the
/// result is here then `Some` is returned, otherwise `None` is returned.
///
/// Note that by polling `future` this means that `future` must be re-polled
/// later if it's to wake up a task.
pub fn poll_noop<F>(future: Pin<&mut F>) -> Option<F::Output>
where
    F: Future,
{
    poll_now(|cx| future.poll(cx))
}
