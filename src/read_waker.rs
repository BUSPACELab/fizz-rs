//! Read-side `Waker` slot shared with C++.
//!
//! Each `ClientConnection` / `ServerConnection` owns an `Arc<ReadWaker>`. A clone
//! (boxed via cxx) is handed to the C++ `FizzClientConnection` /
//! `FizzServerConnection` after the handshake. `poll_read` registers the current
//! task's `Waker` on every poll; the C++ read-side callbacks (`readDataAvailable`
//! and `readEOF`) call `wake_read_waker` to fire whatever `Waker` is registered.
//!
//! This replaces the previous `cx.waker().wake_by_ref(); Poll::Pending`
//! busy-poll, which re-scheduled the task immediately and burned 100% CPU on
//! each worker until bytes landed in the C++ buffer queue.

use std::sync::Mutex;
use std::task::Waker;

/// Read-side waker slot. Shared between the Rust `poll_read` and the C++
/// read-callback via `Arc` + `rust::Box` (cxx copies the `Arc` — see
/// [`ReadWaker::clone_for_cpp`]).
pub struct ReadWaker {
    inner: std::sync::Arc<Mutex<Option<Waker>>>,
}

impl ReadWaker {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(Mutex::new(None)),
        }
    }

    /// Returns a handle that aliases the same inner slot. The returned value is
    /// what we hand to C++ via `rust::Box<ReadWaker>`.
    pub fn clone_for_cpp(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }

    /// Install `waker` as the current waker, replacing any previous one. Called
    /// from `poll_read` at the start of every poll.
    pub fn register(&self, waker: &Waker) {
        let mut slot = self.inner.lock().expect("ReadWaker slot poisoned");
        match slot.as_ref() {
            Some(existing) if existing.will_wake(waker) => {}
            _ => *slot = Some(waker.clone()),
        }
    }

    /// Wake whatever waker was last registered. Safe to call with no waker
    /// installed (e.g. before the first poll) — it's a no-op in that case.
    pub fn wake(&self) {
        let taken = {
            let mut slot = self.inner.lock().expect("ReadWaker slot poisoned");
            slot.take()
        };
        if let Some(w) = taken {
            w.wake();
        }
    }
}

/// Free function exposed to C++ via the cxx bridge.
pub fn wake_read_waker(waker: &ReadWaker) {
    waker.wake();
}
