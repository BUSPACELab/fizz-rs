//! I/O utilities and helper functions for async operations.
//!
//! This module contains helper functions and utilities for bridging between
//! Folly EventBase operations and Tokio async I/O.

use bytes::BytesMut;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use tokio::net::TcpStream;

/// Default buffer size for reads and writes (64KB)
pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

/// Extract the raw file descriptor from a Tokio TcpStream
///
/// This is used to pass sockets to the C++ Fizz library which operates
/// on raw file descriptors.
pub(crate) fn extract_raw_fd(stream: &TcpStream) -> RawFd {
    stream.as_raw_fd()
}

/// Transfer ownership of a TcpStream's file descriptor
///
/// This consumes the TcpStream and returns its raw FD.
/// The caller is responsible for managing the FD lifecycle.
///
/// Sets TCP_NODELAY before handing the FD to C++. Every connection here
/// carries request/response traffic (TLS handshake flights, then RPC or
/// HTTP exchanges), where Nagle's algorithm delays each small write that
/// follows an unacknowledged one by up to a delayed-ACK interval (~40ms
/// on Linux). The C++ side wraps the FD in a folly AsyncSocket without
/// touching the option, and cpp_bench.cpp already sets it for the same
/// reason.
pub(crate) fn take_raw_fd(stream: TcpStream) -> RawFd {
    let _ = stream.set_nodelay(true);
    // Convert TcpStream to std::net::TcpStream first
    stream.into_std()
        .expect("Failed to convert to std::net::TcpStream")
        .into_raw_fd()
}

/// Helper for converting blocking operations to async
pub(crate) async fn spawn_blocking_io<F, T>(f: F) -> std::io::Result<T>
where
    F: FnOnce() -> std::io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
}

/// Buffered wrapper for TLS connections
///
/// This provides buffering for both read and write operations to reduce
/// the number of FFI calls and improve performance.
pub(crate) struct BufferedConnection {
    /// Read buffer - stores data read from FFI that hasn't been consumed yet
    read_buf: BytesMut,

    /// Write buffer - accumulates data to write before flushing to FFI
    write_buf: BytesMut,

    /// Maximum size for read buffer
    read_buf_capacity: usize,

    /// Maximum size for write buffer
    write_buf_capacity: usize,
}

impl BufferedConnection {
    /// Create a new buffered connection with default buffer sizes
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_BUFFER_SIZE, DEFAULT_BUFFER_SIZE)
    }

    /// Create a new buffered connection with custom buffer sizes
    pub fn with_capacity(read_capacity: usize, write_capacity: usize) -> Self {
        Self {
            read_buf: BytesMut::with_capacity(read_capacity),
            write_buf: BytesMut::with_capacity(write_capacity),
            read_buf_capacity: read_capacity,
            write_buf_capacity: write_capacity,
        }
    }

    /// Get a mutable reference to the read buffer
    pub fn read_buf_mut(&mut self) -> &mut BytesMut {
        &mut self.read_buf
    }

    /// Get a reference to the read buffer
    pub fn read_buf(&self) -> &BytesMut {
        &self.read_buf
    }

    /// Get a mutable reference to the write buffer
    pub fn write_buf_mut(&mut self) -> &mut BytesMut {
        &mut self.write_buf
    }

    /// Get a reference to the write buffer
    pub fn write_buf(&self) -> &BytesMut {
        &self.write_buf
    }

    /// Check if read buffer has data available
    pub fn has_read_data(&self) -> bool {
        !self.read_buf.is_empty()
    }

    /// Check if write buffer has data pending
    pub fn has_write_data(&self) -> bool {
        !self.write_buf.is_empty()
    }

    /// Consume data from the read buffer
    ///
    /// This is used by AsyncRead to copy buffered data to the user's buffer.
    pub fn consume_read_buf(&mut self, amt: usize) {
        let _ = self.read_buf.split_to(amt);
    }

    /// Reserve space in the read buffer
    pub fn reserve_read_buf(&mut self, additional: usize) {
        self.read_buf.reserve(additional);
    }

    /// Reserve space in the write buffer
    pub fn reserve_write_buf(&mut self, additional: usize) {
        self.write_buf.reserve(additional);
    }

    /// Clear the write buffer after flushing
    pub fn clear_write_buf(&mut self) {
        self.write_buf.clear();
    }

    /// Get the maximum read buffer capacity
    pub fn read_capacity(&self) -> usize {
        self.read_buf_capacity
    }

    /// Get the maximum write buffer capacity
    pub fn write_capacity(&self) -> usize {
        self.write_buf_capacity
    }
}

impl Default for BufferedConnection {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrapper to make CXX UniquePtr Send-able for spawn_blocking
///
/// # Safety
///
/// This wrapper allows sending CXX UniquePtr across thread boundaries.
/// It is safe because:
///
/// 1. The connection is only accessed by one async task at a time
/// 2. spawn_blocking ensures exclusive access during FFI calls
/// 3. The connection is never accessed concurrently from multiple threads
/// 4. EventBase operations are serialized by the blocking task
///
/// # Invariants
///
/// - Must not be cloned or shared between tasks
/// - Must not be accessed after being sent to spawn_blocking until the task completes
/// - The underlying connection must remain valid for the lifetime of the wrapper
pub(crate) struct SendableConnectionPtr<T> {
    ptr: *mut T,
}

impl<T> SendableConnectionPtr<T> {
    /// Create a new sendable pointer from a mutable reference
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - The reference remains valid for the lifetime of the wrapper
    /// - No other code accesses the connection during spawn_blocking
    pub unsafe fn new(conn: &mut T) -> Self {
        Self {
            ptr: conn as *mut T,
        }
    }

    /// Get a mutable reference to the connection
    ///
    /// # Safety
    ///
    /// The caller must ensure this is called from the spawn_blocking thread
    /// and that no other references exist
    pub unsafe fn as_mut(&self) -> &mut T {
        &mut *self.ptr
    }
}

// SAFETY: We manually implement Send for this wrapper.
// This is safe because the connection is only ever accessed by one thread at a time
// through spawn_blocking, which provides the necessary synchronization.
unsafe impl<T> Send for SendableConnectionPtr<T> {}

/// Wrapper for combining connection and buffer pointers for Send-able reads
///
/// # Safety
///
/// This wrapper allows sending both connection and buffer pointers together.
/// It is safe because:
///
/// 1. Both pointers are only accessed within the spawn_blocking closure
/// 2. The buffer is allocated before the spawn and accessed after completion
/// 3. No other code accesses these pointers during the blocking operation
pub(crate) struct SendableReadBuffer<T> {
    conn_ptr: *mut T,
    buf_ptr: *mut u8,
    buf_len: usize,
}

impl<T> SendableReadBuffer<T> {
    /// Create a new sendable read buffer wrapper
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - Both pointers remain valid for the lifetime of the wrapper
    /// - The buffer has at least `buf_len` bytes of capacity
    /// - No other code accesses these pointers during spawn_blocking
    pub unsafe fn new(conn: &mut T, buf_ptr: *mut u8, buf_len: usize) -> Self {
        Self {
            conn_ptr: conn as *mut T,
            buf_ptr,
            buf_len,
        }
    }

    /// Get the connection, buffer slice, and perform the read operation
    ///
    /// # Safety
    ///
    /// The caller must ensure this is called from the spawn_blocking thread
    pub unsafe fn get_parts(&self) -> (&mut T, &mut [u8]) {
        let conn = &mut *self.conn_ptr;
        let buf_slice = std::slice::from_raw_parts_mut(self.buf_ptr, self.buf_len);
        (conn, buf_slice)
    }
}

// SAFETY: We manually implement Send for this wrapper.
// This is safe because both pointers are only accessed within the spawn_blocking closure
// and the caller ensures proper synchronization.
unsafe impl<T> Send for SendableReadBuffer<T> {}

/// Wrapper for combining connection and data for Send-able writes
///
/// # Safety
///
/// This wrapper allows sending connection pointer and data together.
/// It is safe because:
///
/// 1. Both are only accessed within the spawn_blocking closure
/// 2. The data is owned by the wrapper and moved into spawn_blocking
pub(crate) struct SendableWriteBuffer<T> {
    conn_ptr: *mut T,
    data: Vec<u8>,
}

impl<T> SendableWriteBuffer<T> {
    /// Create a new sendable write buffer wrapper
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - The connection pointer remains valid for the lifetime of the wrapper
    /// - No other code accesses the connection during spawn_blocking
    pub unsafe fn new(conn: &mut T, data: Vec<u8>) -> Self {
        Self {
            conn_ptr: conn as *mut T,
            data,
        }
    }

    /// Get the connection and data for the write operation
    ///
    /// # Safety
    ///
    /// The caller must ensure this is called from the spawn_blocking thread
    pub unsafe fn get_parts(self) -> (*mut T, Vec<u8>) {
        (self.conn_ptr, self.data)
    }
}

// SAFETY: We manually implement Send for this wrapper.
unsafe impl<T> Send for SendableWriteBuffer<T> {}

/// Wrapper for raw pointers to make them Send-able
///
/// # Safety
///
/// This wrapper allows sending raw pointers across thread boundaries.
/// The caller MUST ensure:
/// - The pointer remains valid for the duration of the async operation
/// - Only one task accesses the pointer at a time
/// - Proper cleanup/re-boxing after the operation completes
pub(crate) struct SendableRawPtr<T> {
    ptr: *mut T,
}

impl<T> SendableRawPtr<T> {
    /// Create a new sendable raw pointer
    ///
    /// # Safety
    ///
    /// The caller must ensure the pointer remains valid
    pub unsafe fn new(ptr: *mut T) -> Self {
        Self { ptr }
    }

    /// Get the raw pointer value
    pub fn as_ptr(&self) -> *mut T {
        self.ptr
    }
}

// SAFETY: Raw pointers are Copy
impl<T> Copy for SendableRawPtr<T> {}

// SAFETY: Raw pointers are Clone
impl<T> Clone for SendableRawPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

// SAFETY: We manually implement Send.
// The caller is responsible for ensuring thread safety.
unsafe impl<T> Send for SendableRawPtr<T> {}

