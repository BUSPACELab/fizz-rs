//! Server-side TLS with delegated credentials support.
//!
//! This module provides APIs for creating TLS server contexts configured with
//! delegated credentials and accepting TLS connections.

use crate::bridge::ffi;
use crate::certificates::CertificatePublic;
use crate::credentials::DelegatedCredentialData;
use crate::error::{FizzError, Result};
use crate::io::{take_raw_fd, SendableRawPtr};
use crate::read_waker::ReadWaker;
use std::pin::Pin;
use std::sync::Arc;
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
    /// Crate-internal accessor for the CXX context. Used by `fizz_rs::cpp_bench`.
    pub(crate) fn cxx_ref(&self) -> &ffi::FizzServerContext {
        &*self.inner
    }

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
        let fd = take_raw_fd(socket);

        let ctx_sendable = unsafe {
            SendableRawPtr::new(
                &self.inner as *const _ as *mut cxx::UniquePtr<ffi::FizzServerContext>,
            )
        };

        let conn_sendable = tokio::task::spawn_blocking(
            move || -> Result<SendableRawPtr<cxx::UniquePtr<ffi::FizzServerConnection>>> {
                let ctx = unsafe { &*ctx_sendable.as_ptr() };
                let conn = ffi::server_accept_connection(ctx, fd)?;
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

        ffi::server_connection_handshake_async(conn_inner_box.pin_mut(), Box::new(io_ctx))
            .map_err(|e| FizzError::TlsHandshakeError(e.to_string()))?;

        // SAFETY: raw-pointer dance keeps the CXX UniquePtr alive across the
        // await point without requiring it to be Send.
        let conn_raw = unsafe { SendableRawPtr::new(Box::into_raw(conn_inner_box)) };

        let result = receiver.await.map_err(|_| {
            FizzError::TlsHandshakeError("Handshake channel closed unexpectedly".to_string())
        })?;

        result.map_err(|e| FizzError::TlsHandshakeError(e))?;

        let mut conn_inner_box = unsafe { Box::from_raw(conn_raw.as_ptr()) };

        let read_waker = Arc::new(ReadWaker::new());
        ffi::set_server_read_waker(
            conn_inner_box.pin_mut(),
            Box::new(read_waker.clone_for_cpp()),
        );

        Ok(ServerConnection {
            inner: *conn_inner_box,
            read_waker,
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
    read_waker: Arc<ReadWaker>,
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
        // Register before inspecting state — any wake that races with our check
        // will still hit the registered waker and cause us to be re-polled.
        self.read_waker.register(cx.waker());

        let buf_slice = buf.initialize_unfilled();

        let outcome = match ffi::server_connection_read_or_status(self.inner.pin_mut(), buf_slice) {
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
