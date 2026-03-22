//! Security-oriented handshake tests for delegated-credential TLS.
//!
//! - **Wrong CA:** The client must not complete a handshake when the trust anchor
//!   does not validate the server’s end-entity certificate.
//! - **Mismatched `VerificationInfo` vs server DC:** The client must reject the handshake when
//!   the server’s delegated credential does not match the [`fizz_rs::VerificationInfo`] passed to
//!   [`fizz_rs::ClientTlsContext`].

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use fizz_rs::{
    Certificate, CertificatePublic, ClientTlsContext, CredentialGenerator, DelegatedCredentialData,
    ServerTlsContext, VerificationInfo,
};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::timeout;

const HANDSHAKE_TEST_TIMEOUT: Duration = Duration::from_secs(120);

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// PEM for a self-signed cert unrelated to `fizz.crt` / the real test chain.
fn wrong_ca_path() -> PathBuf {
    fixtures_dir().join("wrong_ca.crt")
}

fn load_parent_generator() -> CredentialGenerator {
    let dir = fixtures_dir();
    let cert_path = dir.join("fizz.crt");
    let key_path = dir.join("fizz.key");
    let cert = Certificate::load_from_files(
        cert_path.to_str().expect("utf-8 path"),
        key_path.to_str().expect("utf-8 path"),
    )
    .expect("load fixture cert; see tests/fixtures and generate_certificate.sh");
    CredentialGenerator::new(cert).expect("credential generator")
}

fn load_server_materials() -> (
    CertificatePublic,
    DelegatedCredentialData,
    VerificationInfo,
    PathBuf,
) {
    let dir = fixtures_dir();
    let cert_path = dir.join("fizz.crt");
    let key_path = dir.join("fizz.key");
    let cert =
        Certificate::load_from_files(cert_path.to_str().unwrap(), key_path.to_str().unwrap())
            .expect("load fixture cert");
    let cert_public =
        CertificatePublic::load_from_file(cert_path.to_str().unwrap()).expect("cert public");
    let generator = CredentialGenerator::new(cert).expect("generator");
    let dc = generator
        .generate("handshake-security-server", 3600)
        .expect("generate DC");
    let verification_info = dc.verification_info();
    (cert_public, dc, verification_info, cert_path)
}

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_fails_when_ca_does_not_trust_server_certificate() {
    let (cert_public, dc, _matching_vi, _server_cert_path) = load_server_materials();
    let wrong_ca = wrong_ca_path();
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
    let (cert_public, dc_for_server, _, ca_path) = load_server_materials();
    let generator = load_parent_generator();
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
