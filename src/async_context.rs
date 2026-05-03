//! Async I/O context types for channel-based communication with C++.
//!
//! Implements the oneshot channel pattern for bridging C++ async callbacks
//! to Rust futures via the CXX bridge.

use tokio::sync::oneshot;

/// Opaque Rust type exposed to C++ via CXX.
///
/// Wraps a [`oneshot::Sender`] so that a C++ callback can signal completion
/// back to the Rust `.await` site without blocking any Tokio worker thread.
pub struct IoContext {
    pub(crate) sender: oneshot::Sender<Result<usize, String>>,
}

impl IoContext {
    pub fn new() -> (Self, oneshot::Receiver<Result<usize, String>>) {
        let (sender, receiver) = oneshot::channel();
        (Self { sender }, receiver)
    }
}

/// Called from C++ when an async operation (handshake, read, write) finishes.
///
/// `bytes` is the transfer count (0 for handshake).
/// `error` is empty on success; otherwise the error description.
pub fn handle_io_result(context: Box<IoContext>, bytes: usize, error: String) {
    let result = if error.is_empty() {
        Ok(bytes)
    } else {
        Err(error)
    };
    let _ = context.sender.send(result);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_io_context_success() {
        let (context, receiver) = IoContext::new();
        handle_io_result(Box::new(context), 42, String::new());
        let result = receiver.await.unwrap();
        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn test_io_context_error() {
        let (context, receiver) = IoContext::new();
        handle_io_result(Box::new(context), 0, "Connection failed".to_string());
        let result = receiver.await.unwrap();
        assert_eq!(result, Err("Connection failed".to_string()));
    }
}
