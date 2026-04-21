//! Shared helpers for integration tests (`tests/*.rs` each compile as their own crate).
#![allow(dead_code)]
// Each test binary only uses a subset of helpers; the compiler still type-checks the whole module.

use std::path::PathBuf;

use fizz_rs::{
    Certificate, CertificatePublic, CredentialGenerator, DelegatedCredentialData, VerificationInfo,
};

pub type FixtureMaterials = (
    CertificatePublic,
    DelegatedCredentialData,
    VerificationInfo,
    PathBuf,
);

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// PEM for a self-signed cert unrelated to `fizz.crt` / the real test chain.
pub fn wrong_ca_path() -> PathBuf {
    fixtures_dir().join("wrong_ca.crt")
}

fn load_fixture_certificate() -> Result<(Certificate, PathBuf), String> {
    let dir = fixtures_dir();
    let cert_path = dir.join("fizz.crt");
    let key_path = dir.join("fizz.key");
    let cert = Certificate::load_from_files(
        cert_path.to_str().ok_or("cert path utf-8")?,
        key_path.to_str().ok_or("key path utf-8")?,
    )
    .map_err(|e| e.to_string())?;
    Ok((cert, cert_path))
}

/// Load parent cert/key from fixtures, issue a delegated credential for `service_name`, return
/// public materials and the path to the parent cert (as CA for the client).
pub fn load_materials(service_name: &str) -> Result<FixtureMaterials, String> {
    let (cert, cert_path) = load_fixture_certificate()?;
    let cert_public = CertificatePublic::load_from_file(
        cert_path
            .to_str()
            .ok_or("cert path utf-8")?,
    )
    .map_err(|e| e.to_string())?;
    let generator = CredentialGenerator::new(cert).map_err(|e| e.to_string())?;
    let dc = generator
        .generate(service_name, 3600)
        .map_err(|e| e.to_string())?;
    let verification_info = dc.verification_info();
    Ok((cert_public, dc, verification_info, cert_path))
}

/// Parent [`Certificate`] loaded from fixtures; use to mint additional DCs in a test.
pub fn load_parent_generator() -> Result<CredentialGenerator, String> {
    let (cert, _) = load_fixture_certificate()?;
    CredentialGenerator::new(cert).map_err(|e| e.to_string())
}
