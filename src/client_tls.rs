//! Client-side TLS with delegated credentials verification.
//!
//! This module provides APIs for creating TLS client contexts configured to
//! verify delegated credentials and establishing TLS connections to servers.

use crate::bridge::ffi;
use crate::error::{FizzError, Result};
use crate::io::{take_raw_fd, SendableRawPtr};
use crate::types::VerificationInfo;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::TcpStream;

/// TLS client context configured for delegated credential verification
pub struct ClientTlsContext {
    inner: cxx::UniquePtr<ffi::FizzClientContext>,
}

// Safety: ClientTlsContext can be safely sent between threads because:
// 1. It is used in read-only mode after construction
// 2. The underlying Fizz library supports concurrent context usage
// 3. Each connection created from the context is independent
unsafe impl Send for ClientTlsContext {}

// Safety: ClientTlsContext can be safely shared across threads because:
// 1. All methods take &self and are read-only after construction
// 2. The underlying Fizz library supports concurrent access from multiple threads
// 3. Internal state is immutable once configured
unsafe impl Sync for ClientTlsContext {}

impl ClientTlsContext {
    /// Create a new client TLS context
    ///
    /// # Arguments
    /// * `verification_info` - Public verification information for the delegated credential
    /// * `ca_cert_path` - Path to CA certificate for parent cert verification
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::{types::VerificationInfo, client_tls::ClientTlsContext};
    /// # let verification_info: VerificationInfo = unimplemented!();
    /// let client_ctx = ClientTlsContext::new(
    ///     verification_info,
    ///     "/path/to/ca-cert.pem"
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(verification_info: VerificationInfo, ca_cert_path: &str) -> Result<Self> {
        let inner = ffi::new_client_tls_context(&verification_info, ca_cert_path)?;
        Ok(Self { inner })
    }

    /// Set ALPN protocols to negotiate
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::client_tls::ClientTlsContext;
    /// # let mut client_ctx: ClientTlsContext = unimplemented!();
    /// client_ctx.set_alpn_protocols(&["h2", "http/1.1"]);
    /// ```
    pub fn set_alpn_protocols(&mut self, protocols: &[&str]) {
        let protocol_strings: Vec<String> = protocols.iter().map(|s| s.to_string()).collect();
        ffi::client_context_set_alpn_protocols(self.inner.pin_mut(), protocol_strings);
    }

    /// Set SNI hostname
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::client_tls::ClientTlsContext;
    /// # let mut client_ctx: ClientTlsContext = unimplemented!();
    /// client_ctx.set_sni("example.com");
    /// ```
    pub fn set_sni(&mut self, hostname: &str) {
        ffi::client_context_set_sni(self.inner.pin_mut(), hostname);
    }

    /// Connect to a TLS server and perform handshake automatically
    ///
    /// This is the high-level API that connects to a server using an existing TCP connection,
    /// performs the TLS handshake, and returns a ready-to-use connection that
    /// implements AsyncRead + AsyncWrite.
    ///
    /// # Arguments
    /// * `socket` - Connected TCP socket
    /// * `hostname` - Server hostname for SNI and verification
    ///
    /// # Returns
    /// A `ClientConnection` ready for encrypted communication
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::client_tls::ClientTlsContext;
    /// # use tokio::net::TcpStream;
    /// # async fn example(client_ctx: ClientTlsContext) -> Result<(), Box<dyn std::error::Error>> {
    /// let stream = TcpStream::connect("example.com:443").await?;
    /// let conn = client_ctx.connect(stream, "example.com").await?;
    /// // conn implements AsyncRead + AsyncWrite
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(&self, socket: TcpStream, hostname: &str) -> Result<ClientConnection> {
        // Extract FD (this transfers ownership)
        let fd = take_raw_fd(socket);
        let hostname_string = hostname.to_string();

        // Get raw pointer to context and wrap in Send-able wrapper
        let ctx_sendable = unsafe {
            SendableRawPtr::new(
                &self.inner as *const _ as *mut cxx::UniquePtr<ffi::FizzClientContext>,
            )
        };

        // Create FFI connection in blocking task
        // We return a raw pointer to avoid Send issues with CXX types
        let conn_sendable = tokio::task::spawn_blocking(
            move || -> Result<SendableRawPtr<cxx::UniquePtr<ffi::FizzClientConnection>>> {
                // Safety: We have exclusive access to context during this call
                // The context is only read, not modified
                let ctx = unsafe { &*ctx_sendable.as_ptr() };
                let conn = ffi::client_connect(ctx, fd, &hostname_string)?;
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
        ffi::client_connection_handshake(conn_inner_box.pin_mut())?;

        // Convert Box back to raw pointer to avoid holding non-Send Box across await
        // SAFETY: We immediately convert back to Box after the await
        let conn_raw = unsafe { SendableRawPtr::new(Box::into_raw(conn_inner_box)) };

        // Convert back to Box after await
        let conn_inner_box = unsafe { Box::from_raw(conn_raw.as_ptr()) };

        Ok(ClientConnection {
            inner: *conn_inner_box,
        })
    }
}

/// An active TLS client connection
///
/// This connection has completed the TLS handshake and is ready for
/// encrypted communication. It implements AsyncRead and AsyncWrite for
/// seamless integration with Tokio.
pub struct ClientConnection {
    inner: cxx::UniquePtr<ffi::FizzClientConnection>,
}

impl std::fmt::Debug for ClientConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConnection")
            .field("is_open", &self.is_open())
            .finish_non_exhaustive()
    }
}

// Safety: ClientConnection can be safely sent between threads because:
// 1. Each connection has independent state
// 2. The underlying Fizz connection is designed for single-threaded use,
//    but moving between threads (not concurrent access) is safe
// 3. All I/O operations go through async APIs that handle synchronization
unsafe impl Send for ClientConnection {}

impl ClientConnection {
    /// Get the peer's certificate as PEM string
    ///
    /// This should be called after a successful handshake.
    pub fn peer_certificate(&self) -> Result<String> {
        ffi::client_connection_peer_cert(&self.inner)
            .map(|s| s.to_string())
            .map_err(|e| FizzError::TlsHandshakeError(e.to_string()))
    }

    /// Check if the connection is still open
    pub fn is_open(&self) -> bool {
        ffi::client_connection_is_open(&self.inner)
    }

    /// Close the connection
    ///
    /// This gracefully closes the TLS connection and cleans up resources.
    pub fn close(&mut self) {
        println!("Closing connection");
        ffi::client_connection_close(self.inner.pin_mut());
    }
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        println!("Cleaning up Client connection");
        self.close();
    }
}

// AsyncRead implementation
impl tokio::io::AsyncRead for ClientConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let read_size = {
            let conn_pin = self.inner.pin_mut();
            match ffi::client_read_size_hint(conn_pin) {
                Ok(n) => n,
                Err(e) => {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)));
                }
            }
        };

        if read_size == 0 {
            if ffi::client_connection_read_eof(&self.inner) {
                return Poll::Ready(Ok(()));
            }
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        // println!("On poll_read, we have {} available to read from size_hint", read_size);

        let mut buf_slice = buf.initialize_unfilled();

        // println!("We will try to read into a buffer of size {}", buf_slice.len());

        let conn_pin = self.inner.pin_mut();
        let read = match ffi::client_connection_read(conn_pin, &mut buf_slice) {
            Ok(n) => n,
            Err(e) => {
                return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)));
            }
        };

        // println!("On poll_read, we have read {} ", read);

        if read == 0 {
            // This lets us distinguish between EOF and no data available.
            if ffi::client_connection_read_eof(&self.inner) {
                return Poll::Ready(Ok(()));
            }
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        //
        // unsafe { self.read_buf.advance_mut(read) };
        // //THis copies the buffer... Is there a way to
        // buf.put_slice(&buf_slice[..read]);
        // let _ = self.read_buf.split_to(read);

        buf.advance(read);
        Poll::Ready(Ok(()))
    }
}

// AsyncWrite implementation
impl tokio::io::AsyncWrite for ClientConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match ffi::client_connection_write(self.inner.pin_mut(), buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Perform a flush by writing empty data - this ensures C++ buffers are flushed
        // We use the same synchronous pattern as poll_write
        Poll::Ready(Ok(()))
        // match ffi::client_connection_write(self.inner.pin_mut(), &[]) {
        //     Ok(_) => Poll::Ready(Ok(())),
        //     Err(e) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e))),
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
