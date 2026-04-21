//! Security-oriented handshake tests for delegated-credential TLS.
//!
//! - **Wrong CA:** The client must not complete a handshake when the trust anchor
//!   does not validate the server’s end-entity certificate.
//! - **Mismatched `VerificationInfo` vs server DC:** The client must reject the handshake when
//!   the server’s delegated credential does not match the [`fizz_rs::VerificationInfo`] passed to
//!   [`fizz_rs::ClientTlsContext`].
//! - **Happy path:** Matching CA, parent cert, delegated credential, and client `VerificationInfo`
//!   from the same issuance, then a small application-data round-trip after the handshake.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use fizz_rs::{
    CertificatePublic, ClientTlsContext, DelegatedCredentialData, ServerTlsContext, VerificationInfo,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::timeout;

const HANDSHAKE_TEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Payload sent on the happy-path TLS stream after handshake (client → server).
const HAPPY_PATH_PAYLOAD: &[u8] = b"dc-happy-path-roundtrip";

async fn server_handshake_only(
    listener: TcpListener,
    cert_public: CertificatePublic,
    dc: DelegatedCredentialData,
) -> Result<(), String> {
    let (socket, _) = listener
        .accept()
        .await
        .map_err(|e| format!("accept: {e}"))?;
    let tls = ServerTlsContext::new(cert_public, dc).map_err(|e| format!("server ctx: {e}"))?;
    let _conn = tls
        .accept_from_stream(socket)
        .await
        .map_err(|e| format!("server handshake: {e}"))?;
    Ok(())
}

async fn server_happy_path_roundtrip(
    listener: TcpListener,
    cert_public: CertificatePublic,
    dc: DelegatedCredentialData,
    expected: &[u8],
) -> Result<(), String> {
    let (socket, _) = listener
        .accept()
        .await
        .map_err(|e| format!("accept: {e}"))?;
    let tls = ServerTlsContext::new(cert_public, dc).map_err(|e| format!("server ctx: {e}"))?;
    let mut conn = tls
        .accept_from_stream(socket)
        .await
        .map_err(|e| format!("server handshake: {e}"))?;

    let mut buf = vec![0u8; expected.len()];
    conn.read_exact(&mut buf)
        .await
        .map_err(|e| format!("read_exact: {e}"))?;
    if buf.as_slice() != expected {
        return Err(format!(
            "payload mismatch: got {} bytes, expected {:?}",
            buf.len(),
            expected
        ));
    }
    Ok(())
}

async fn client_handshake_only(
    addr: SocketAddr,
    verification_info: VerificationInfo,
    ca_cert: &PathBuf,
) -> fizz_rs::Result<()> {
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let client =
        ClientTlsContext::new(verification_info, ca_cert.to_str().expect("ca path utf-8"))?;
    let _conn = client.connect(stream, "localhost").await?;
    Ok(())
}

async fn client_happy_path_roundtrip(
    addr: SocketAddr,
    verification_info: VerificationInfo,
    ca_cert: &PathBuf,
    payload: &[u8],
) -> fizz_rs::Result<()> {
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let client =
        ClientTlsContext::new(verification_info, ca_cert.to_str().expect("ca path utf-8"))?;
    let mut conn = client.connect(stream, "localhost").await?;
    conn.write_all(payload).await?;
    conn.flush().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delegated_tls_happy_path_handshake_and_round_trip() {
    let (cert_public, dc, verification_info, ca_path) =
        common::load_materials("happy-path-roundtrip").expect(
            "load fixture cert; see tests/fixtures and generate_certificate.sh",
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let (started_tx, started_rx) = oneshot::channel();
    let expected = HAPPY_PATH_PAYLOAD.to_vec();
    let server = tokio::spawn(async move {
        let _ = started_tx.send(());
        server_happy_path_roundtrip(listener, cert_public, dc, &expected).await
    });
    started_rx.await.expect("server started");

    let client = tokio::spawn(async move {
        client_happy_path_roundtrip(addr, verification_info, &ca_path, HAPPY_PATH_PAYLOAD).await
    });

    let outcome = timeout(HANDSHAKE_TEST_TIMEOUT, async move {
        let c = client.await.expect("client join");
        let s = server.await.expect("server join");
        (c, s)
    })
    .await;

    let (client_res, server_res) = outcome.expect("happy-path test should finish (no hang)");
    client_res.expect("client handshake and write");
    server_res.expect("server handshake and read");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_fails_when_ca_does_not_trust_server_certificate() {
    let (cert_public, dc, _matching_vi, _server_cert_path) =
        common::load_materials("handshake-security-server").expect(
            "load fixture cert; see tests/fixtures and generate_certificate.sh",
        );
    let wrong_ca = common::wrong_ca_path();
    assert!(
        wrong_ca.is_file(),
        "missing {}; generate with openssl req -x509 ...",
        wrong_ca.display()
    );

    // Use a different DC than the matching case only to keep names distinct; CA mismatch alone
    // should fail certificate verification before DC semantics matter.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let (started_tx, started_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let _ = started_tx.send(());
        server_handshake_only(listener, cert_public, dc).await
    });
    started_rx.await.expect("server started");

    let client =
        tokio::spawn(async move { client_handshake_only(addr, _matching_vi, &wrong_ca).await });

    let outcome = timeout(HANDSHAKE_TEST_TIMEOUT, async move {
        let c = client.await.expect("client join");
        let s = server.await.expect("server join");
        (c, s)
    })
    .await;

    let (client_res, server_res) = outcome.expect("handshake test should finish (no hang)");

    assert!(
        client_res.is_err(),
        "expected client handshake to fail: wrong CA must not trust the server certificate (got {client_res:?})"
    );

    // Server may report handshake error or success depending on teardown; client failure is the
    // security signal we care about.
    let _ = server_res;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_fails_when_verification_info_does_not_match_server_delegated_credential() {
    let (cert_public, dc_for_server, _, ca_path) =
        common::load_materials("handshake-security-server").expect(
            "load fixture cert; see tests/fixtures and generate_certificate.sh",
        );
    let generator = common::load_parent_generator().expect("credential generator");
    let dc_other = generator
        .generate("different-service-name", 3600)
        .expect("second DC");
    let wrong_client_info = dc_other.verification_info();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let (started_tx, started_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let _ = started_tx.send(());
        server_handshake_only(listener, cert_public, dc_for_server).await
    });
    started_rx.await.expect("server started");

    let client =
        tokio::spawn(async move { client_handshake_only(addr, wrong_client_info, &ca_path).await });

    let outcome = timeout(HANDSHAKE_TEST_TIMEOUT, async move {
        let c = client.await.expect("client join");
        let s = server.await.expect("server join");
        (c, s)
    })
    .await;

    let (client_res, server_res) = outcome.expect("handshake test should finish (no hang)");

    assert!(
        client_res.is_err(),
        "client must not complete TLS when VerificationInfo does not match the server DC \
         (got {client_res:?}; server={server_res:?})"
    );
    let _ = server_res;
}
