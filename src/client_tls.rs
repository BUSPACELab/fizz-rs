//! Client-side TLS with delegated credentials verification.
//!
//! This module provides APIs for creating TLS client contexts configured to
//! verify delegated credentials and establishing TLS connections to servers.

use crate::bridge::ffi;
use crate::error::{FizzError, Result};
use crate::io::{take_raw_fd, SendableRawPtr};
use crate::read_waker::ReadWaker;
use crate::types::VerificationInfo;
use std::pin::Pin;
use std::sync::Arc;
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
    /// Crate-internal accessor for the CXX context. Used by `fizz_rs::cpp_bench`.
    pub(crate) fn cxx_ref(&self) -> &ffi::FizzClientContext {
        &*self.inner
    }

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

    /// Create a client TLS context that does **not** advertise or verify a
    /// delegated credential. Used as the "regular TLS" baseline for
    /// DC-overhead benchmarks.
    pub fn new_no_dc(ca_cert_path: &str) -> Result<Self> {
        let inner = ffi::new_client_tls_context_no_dc(ca_cert_path)?;
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
        let fd = take_raw_fd(socket);
        let hostname_string = hostname.to_string();

        let ctx_sendable = unsafe {
            SendableRawPtr::new(
                &self.inner as *const _ as *mut cxx::UniquePtr<ffi::FizzClientContext>,
            )
        };

        let conn_sendable = tokio::task::spawn_blocking(
            move || -> Result<SendableRawPtr<cxx::UniquePtr<ffi::FizzClientConnection>>> {
                let ctx = unsafe { &*ctx_sendable.as_ptr() };
                let conn = ffi::client_connect(ctx, fd, &hostname_string)?;
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

        let mut conn_inner_box = unsafe { Box::from_raw(conn_sendable.as_ptr()) };

        let (io_ctx, receiver) = crate::async_context::IoContext::new();

        ffi::client_connection_handshake_async(conn_inner_box.pin_mut(), Box::new(io_ctx))
            .map_err(|e| FizzError::TlsHandshakeError(e.to_string()))?;

        // SAFETY: raw-pointer dance keeps the CXX UniquePtr alive across the
        // await point without requiring it to be Send.
        let conn_raw = unsafe { SendableRawPtr::new(Box::into_raw(conn_inner_box)) };

        let result = receiver.await.map_err(|_| {
            FizzError::TlsHandshakeError(
                "Handshake channel closed unexpectedly".to_string(),
            )
        })?;

        result.map_err(|e| FizzError::TlsHandshakeError(e))?;

        let mut conn_inner_box = unsafe { Box::from_raw(conn_raw.as_ptr()) };

        let read_waker = Arc::new(ReadWaker::new());
        ffi::set_client_read_waker(
            conn_inner_box.pin_mut(),
            Box::new(read_waker.clone_for_cpp()),
        );

        Ok(ClientConnection {
            inner: *conn_inner_box,
            read_waker,
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
    read_waker: Arc<ReadWaker>,
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
        ffi::client_connection_close(self.inner.pin_mut());
    }
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
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
        // Register before inspecting state — any wake that races with our check
        // will still hit the registered waker and cause us to be re-polled.
        self.read_waker.register(cx.waker());

        let buf_slice = buf.initialize_unfilled();

        let outcome = match ffi::client_connection_read_or_status(self.inner.pin_mut(), buf_slice) {
            Ok(o) => o,
            Err(e) => {
                return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)));
            }
        };

        if outcome.bytes_read > 0 {
            buf.advance(outcome.bytes_read as usize);
            return Poll::Ready(Ok(()));
        }

        if outcome.eof {
            return Poll::Ready(Ok(()));
        }

        Poll::Pending
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
