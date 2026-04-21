//! Server-side TLS with delegated credentials support.
//!
//! This module provides APIs for creating TLS server contexts configured with
//! delegated credentials and accepting TLS connections.

use crate::bridge::ffi;
use crate::certificates::CertificatePublic;
use crate::credentials::DelegatedCredentialData;
use crate::error::{FizzError, Result};
use crate::io::{take_raw_fd, SendableRawPtr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::{TcpListener, TcpStream};

/// TLS server context configured with delegated credentials
pub struct ServerTlsContext {
    inner: cxx::UniquePtr<ffi::FizzServerContext>,
}

// Safety: ServerTlsContext can be safely sent between threads because:
// 1. It is used in read-only mode after construction
// 2. The underlying Fizz library supports concurrent context usage
// 3. Each connection created from the context is independent
unsafe impl Send for ServerTlsContext {}

// Safety: ServerTlsContext can be safely shared across threads because:
// 1. All methods take &self and are read-only after construction
// 2. The underlying Fizz library supports concurrent access from multiple threads
// 3. Internal state is immutable once configured
unsafe impl Sync for ServerTlsContext {}

impl ServerTlsContext {
    /// Create a new server TLS context
    ///
    /// # Security
    /// This function takes `CertificatePublic` (without private key) to enforce
    /// RFC 9345 security requirements: servers using delegated credentials should
    /// NEVER have access to the parent certificate's private key. Only the
    /// credential manager/sidecar that generates credentials needs the private key.
    ///
    /// # Arguments
    /// * `cert` - Parent certificate (public component only, NO private key)
    /// * `delegated_cred` - Delegated credential to present to clients
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::{certificates::CertificatePublic, credentials::DelegatedCredentialData, server_tls::ServerTlsContext};
    /// # let cert: CertificatePublic = unimplemented!();
    /// # let delegated_cred: DelegatedCredentialData = unimplemented!();
    /// let server_ctx = ServerTlsContext::new(cert, delegated_cred)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(cert: CertificatePublic, delegated_cred: DelegatedCredentialData) -> Result<Self> {
        let inner = ffi::new_server_tls_context(cert.as_inner(), &delegated_cred.inner)?;
        Ok(Self { inner })
    }

    /// Set ALPN protocols to advertise
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::server_tls::ServerTlsContext;
    /// # let mut server_ctx: ServerTlsContext = unimplemented!();
    /// server_ctx.set_alpn_protocols(&["h2", "http/1.1"]);
    /// ```
    pub fn set_alpn_protocols(&mut self, protocols: &[&str]) {
        let protocol_strings: Vec<String> = protocols.iter().map(|s| s.to_string()).collect();
        ffi::server_context_set_alpn_protocols(self.inner.pin_mut(), protocol_strings);
    }

    /// Accept a TLS connection and perform handshake automatically
    ///
    /// This is the high-level API that accepts a TCP connection from a listener,
    /// performs the TLS handshake, and returns a ready-to-use connection that
    /// implements AsyncRead + AsyncWrite.
    ///
    /// # Arguments
    /// * `listener` - TCP listener to accept from
    ///
    /// # Returns
    /// A `ServerConnection` ready for encrypted communication
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::server_tls::ServerTlsContext;
    /// # use tokio::net::TcpListener;
    /// # async fn example(server_ctx: ServerTlsContext) -> Result<(), Box<dyn std::error::Error>> {
    /// let listener = TcpListener::bind("127.0.0.1:8443").await?;
    /// let conn = server_ctx.accept(&listener).await?;
    /// // conn implements AsyncRead + AsyncWrite
    /// # Ok(())
    /// # }
    /// ```
    pub async fn accept(&self, listener: &TcpListener) -> Result<ServerConnection> {
        // Accept TCP connection
        let (socket, _addr) = listener.accept().await.map_err(|e| FizzError::IoError(e))?;

        // Accept TLS connection from the socket
        self.accept_from_stream(socket).await
    }

    /// Accept a TLS connection from an existing TCP stream
    ///
    /// This allows accepting a TLS connection from a socket that was obtained
    /// by other means (e.g., from a connection pool or proxy).
    ///
    /// # Arguments
    /// * `socket` - TCP stream for the TLS connection
    ///
    /// # Returns
    /// A `ServerConnection` ready for encrypted communication
    pub async fn accept_from_stream(&self, socket: TcpStream) -> Result<ServerConnection> {
        // Extract FD (this transfers ownership)
        let fd = take_raw_fd(socket);

        // Get raw pointer to context and wrap in Send-able wrapper
        let ctx_sendable = unsafe {
            SendableRawPtr::new(
                &self.inner as *const _ as *mut cxx::UniquePtr<ffi::FizzServerContext>,
            )
        };

        // Create FFI connection in blocking task
        // We return a raw pointer to avoid Send issues with CXX types
        let conn_sendable = tokio::task::spawn_blocking(
            move || -> Result<SendableRawPtr<cxx::UniquePtr<ffi::FizzServerConnection>>> {
                // Safety: We have exclusive access to context during this call
                // The context is only read, not modified
                let ctx = unsafe { &*ctx_sendable.as_ptr() };
                let conn = ffi::server_accept_connection(ctx, fd)?;
                // Box the connection and return sendable raw pointer
                Ok(unsafe { SendableRawPtr::new(Box::into_raw(Box::new(conn))) })
            },
        )
        .await
        .map_err(|e| {
            FizzError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to spawn blocking task: {}", e),
            ))
        })??;

        // Re-box the connection pointer first
        let mut conn_inner_box = unsafe { Box::from_raw(conn_sendable.as_ptr()) };

        // Perform async handshake using oneshot channel
        ffi::server_connection_handshake(conn_inner_box.pin_mut())?;

        // Convert Box back to raw pointer to avoid holding non-Send Box across await
        // SAFETY: We immediately convert back to Box after the await
        let conn_raw = unsafe { SendableRawPtr::new(Box::into_raw(conn_inner_box)) };

        // Convert back to Box after await
        let conn_inner_box = unsafe { Box::from_raw(conn_raw.as_ptr()) };

        Ok(ServerConnection {
            inner: *conn_inner_box,
        })
    }
}

/// An active TLS server connection
///
/// This connection has completed the TLS handshake and is ready for
/// encrypted communication. It implements AsyncRead and AsyncWrite for
/// seamless integration with Tokio.
pub struct ServerConnection {
    inner: cxx::UniquePtr<ffi::FizzServerConnection>,
}

impl std::fmt::Debug for ServerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConnection")
            .field("is_open", &self.is_open())
            .finish_non_exhaustive()
    }
}

// Safety: ServerConnection can be safely sent between threads because:
// 1. Each connection has independent state
// 2. The underlying Fizz connection is designed for single-threaded use,
//    but moving between threads (not concurrent access) is safe
// 3. All I/O operations go through async APIs that handle synchronization
unsafe impl Send for ServerConnection {}

impl ServerConnection {
    /// Check if the connection is still open
    pub fn is_open(&self) -> bool {
        ffi::server_connection_is_open(&self.inner)
    }

    /// Close the connection
    ///
    /// This gracefully closes the TLS connection and cleans up resources.
    pub fn close(&mut self) {
        ffi::server_connection_close(self.inner.pin_mut());
    }
}

// AsyncRead implementation
impl tokio::io::AsyncRead for ServerConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let conn_pin = self.inner.pin_mut();
        let read_size = match ffi::server_read_size_hint(conn_pin) {
            Ok(n) => n,
            Err(e) => {
                return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)));
            }
        };

        if read_size == 0 {
            if ffi::server_connection_read_eof(&self.inner) {
                return Poll::Ready(Ok(()));
            }
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        // //If we won't be able to read the buffer without reallocation, we need to reallocate first.
        // if self.read_buf.remaining() <= read_size || self.read_buf.capacity() <= read_size {
        //     self.read_buf.reserve(8192);
        // }
        //

        let buf_slice = buf.initialize_unfilled();

        //Take the initialized_buffer, write into it, advance it.
        //SAFETY: We KNOW length of read_slice is at least as big as the size we are about to read.
        //As for the MaybeUninit, we know we are going to fill at most read_size bytes into the buffer.
        //This is handled by the call to advance
        // Get a slice to read into
        // let chunk = self.read_buf.chunk_mut();
        // let buf_ptr = chunk.as_mut_ptr();
        // let buf_len = chunk.len();
        // let mut buf_slice = unsafe { std::slice::from_raw_parts_mut(buf_ptr, buf_len) };

        let read = match ffi::server_connection_read(self.inner.pin_mut(), buf_slice) {
            Ok(n) => n,
            Err(e) => {
                return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)));
            }
        };

        if read == 0 {
            // This lets us distinguish between EOF and no data available.
            if ffi::server_connection_read_eof(&self.inner) {
                return Poll::Ready(Ok(()));
            }
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        buf.advance(read);
        Poll::Ready(Ok(()))
    }
}

// AsyncWrite implementation
impl tokio::io::AsyncWrite for ServerConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // if buf.is_empty() {
        //     return Poll::Ready(Ok(0));
        // }

        match ffi::server_connection_write(self.inner.pin_mut(), &buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
        // match ffi::server_connection_write(self.inner.pin_mut(), &[]) {
        //     Ok(_) => Poll::Ready(Ok(())),
        //     Err(e) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
        // }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Flush any pending writes first
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                // Flush complete, close the connection
                self.close();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}
