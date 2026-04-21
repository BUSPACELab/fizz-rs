//! Reproduces [BUSPACELab/fizz-rs#1](https://github.com/BUSPACELab/fizz-rs/issues/1): EOF is not
//! observed on the server after the client shuts down the TLS stream, so `read_to_string` (and
//! similar `AsyncRead` loops) never complete.
//!
//! **Expected behavior:** After the client sends payload and `shutdown().await`, the server
//! eventually reads any remaining decrypted data and then sees EOF; `read_to_string` returns
//! with an empty string (or the trailing bytes only).
//!
//! **Current bug:** `ServerConnection`/`ClientConnection` `poll_read` treats zero-byte reads as
//! `Poll::Pending` with a self-wake, so EOF is never surfaced to Tokio.
//!
//! This test uses a short wall-clock timeout so a hung server fails fast instead of blocking CI.

mod common;

use std::time::Duration;

use fizz_rs::{
    CertificatePublic, ClientTlsContext, DelegatedCredentialData, ServerTlsContext,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::timeout;

/// UTF-8 body sent after the big-endian `i32` length prefix (must match `write_i32` / `read_i32`).
const EOF_REPRO_PAYLOAD: &str = "Text sent via delegated TLS!";

/// Same framing as `demo/fizz-rs`: `i32` length prefix then UTF-8 body (here we send a fixed `i32`
/// and a string like the demo).
async fn run_server(
    listener: TcpListener,
    cert_public: CertificatePublic,
    dc: DelegatedCredentialData,
) -> Result<String, String> {
    let (socket, _) = listener
        .accept()
        .await
        .map_err(|e| format!("accept: {e}"))?;

    let tls = ServerTlsContext::new(cert_public, dc).map_err(|e| format!("server ctx: {e}"))?;
    let mut conn = tls
        .accept_from_stream(socket)
        .await
        .map_err(|e| format!("handshake: {e}"))?;

    let n = conn
        .read_i32()
        .await
        .map_err(|e| format!("read_i32: {e}"))?;

    let expected = EOF_REPRO_PAYLOAD.len() as i32;
    if n != expected {
        return Err(format!("unexpected i32: {n} (expected {expected})"));
    }

    // After the client sends TLS shutdown, the server should see EOF on the application stream.
    let mut rest = String::new();
    conn.read_to_string(&mut rest)
        .await
        .map_err(|e| format!("read_to_string (EOF): {e}"))?;
    Ok(rest)
}

async fn run_client(
    addr: std::net::SocketAddr,
    verification_info: fizz_rs::VerificationInfo,
    ca: std::path::PathBuf,
) -> Result<(), String> {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("tcp connect: {e}"))?;

    let client = ClientTlsContext::new(verification_info, ca.to_str().ok_or("ca path utf-8")?)
        .map_err(|e| format!("client ctx: {e}"))?;

    let mut conn = client
        .connect(stream, "localhost")
        .await
        .map_err(|e| format!("client handshake: {e}"))?;

    conn.write_i32(EOF_REPRO_PAYLOAD.len() as i32)
        .await
        .map_err(|e| format!("write_i32: {e}"))?;
    conn.write_all(EOF_REPRO_PAYLOAD.as_bytes())
        .await
        .map_err(|e| format!("write_all: {e}"))?;
    conn.flush().await.map_err(|e| format!("flush: {e}"))?;
    conn.shutdown()
        .await
        .map_err(|e| format!("shutdown: {e}"))?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_observes_eof_after_client_shutdown() {
    let (cert_public, dc, verification_info, ca_path) = common::load_materials("eof-repro-test")
        .expect(
            "load fixtures; run openssl per generate_certificate.sh in tests/fixtures if missing",
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let (started_tx, started_rx) = oneshot::channel();

    let server_handle = tokio::spawn(async move {
        let _ = started_tx.send(());
        run_server(listener, cert_public, dc).await
    });

    started_rx.await.expect("server started");

    let client_handle = tokio::spawn(run_client(addr, verification_info, ca_path));

    const SERVER_EOF_TIMEOUT: Duration = Duration::from_secs(8);

    let server_out = timeout(SERVER_EOF_TIMEOUT, server_handle)
        .await
        .expect("server task should finish within timeout (regression: hung on EOF)");

    let server_result = server_out.expect("server join");
    let client_result = client_handle.await.expect("client join");

    client_result.expect("client");

    let body = server_result.expect("server completed read_to_string after EOF");
    assert_eq!(body, EOF_REPRO_PAYLOAD);
}
