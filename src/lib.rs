//! # fizz_rs
//!
//! A Rust library providing TLS primitives for Delegated Credentials (RFC 9345)
//! using the Fizz TLS library via CXX FFI bindings.
//!
//! This library provides **TLS primitives only** - no HTTP servers, no service
//! orchestration, just core TLS and credential operations.
//!
//! ## Features
//!
//! - Certificate loading and management
//! - Delegated credential generation with self-verification
//! - Server-side TLS with delegated credentials
//! - Client-side TLS with delegated credential verification
//! - Full Tokio integration with AsyncRead/AsyncWrite support
//!
//! ## Example
//!
//! ```no_run
//! use fizz_rs::{Certificate, CredentialGenerator};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Load parent certificate
//! let cert = Certificate::load_from_files("cert.pem", "key.pem")?;
//!
//! // Generate delegated credential
//! let generator = CredentialGenerator::new(cert)?;
//! let credential = generator.generate("my-service", 7 * 24 * 3600)?; // 7 days
//!
//! // Self-verify the credential
//! assert!(generator.verify(&credential)?);
//! # Ok(())
//! # }
//! ```

// Re-export CXX types that users might need
pub use cxx::{UniquePtr, SharedPtr};

// Module declarations
// FFI declares stubs (e.g. `load_delegated_credential_from_pem`) not wired from Rust yet.
#[allow(dead_code)]
mod bridge;
// pub mod async_context;
pub mod error;
pub mod types;
pub mod certificates;
pub mod credentials;
pub mod server_tls;
pub mod client_tls;
#[allow(dead_code)]
pub mod io;

// Re-export main types for convenience
pub use error::{FizzError, Result};
pub use types::*;
pub use certificates::{Certificate, PrivateKey, CertificatePublic};
pub use credentials::{CredentialGenerator, DelegatedCredentialData};
pub use server_tls::{ServerTlsContext, ServerConnection};
pub use client_tls::{ClientTlsContext, ClientConnection};