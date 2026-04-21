//! CXX bridge definitions for Fizz TLS FFI.
//!
//! This module defines the FFI boundary between Rust and C++ using the CXX framework.
//! All shared types, opaque types, and FFI functions are declared here.

// Re-export async context items for use in bridge
// use crate::async_context::{IoContext, handle_io_result};

#[cxx::bridge]
pub mod ffi {
    // ============================================================================
    // Shared Structs (visible to both Rust and C++)
    // ============================================================================

    /// Raw delegated credential data structure
    #[derive(Debug, Clone)]
    pub struct DelegatedCredential {
        /// Validity time in seconds from certificate's notBefore
        pub valid_time: u32,
        /// Signature scheme for handshake signature verification
        pub expected_verify_scheme: u16,
        /// DER-encoded public key (hex string)
        pub public_key_der: String,
        /// Signature scheme used to sign the credential
        pub credential_scheme: u16,
        /// Signature over the credential (hex string)
        pub signature: String,
    }

    /// Complete delegated credential with metadata
    #[derive(Debug, Clone)]
    pub struct ServiceCredential {
        /// Service name this credential is for
        pub service_name: String,
        /// The delegated credential itself
        pub credential: DelegatedCredential,
        /// Private key for the credential (PEM format)
        pub private_key_pem: String,
        /// Public key in DER format (hex string)
        pub public_key_der: String,
        /// When the credential was created (Unix timestamp)
        pub created_at: u64,
        /// When the credential expires (Unix timestamp)
        pub expires_at: u64,
        /// Combined PEM format (credential + private key)
        pub credential_pem: String,
    }

    /// Public verification information for clients
    #[derive(Debug, Clone)]
    pub struct VerificationInfo {
        /// Service name
        pub service_name: String,
        /// Validity time in seconds
        pub valid_time: u32,
        /// Expected signature scheme for verification
        pub expected_verify_scheme: u16,
        /// Public key in DER format (hex string)
        pub public_key_der: String,
        /// Expiration timestamp (Unix timestamp)
        pub expires_at: u64,
    }

    /// Certificate and private key data
    #[derive(Debug, Clone)]
    pub struct CertificateData {
        /// Certificate in PEM format
        pub cert_pem: String,
        /// Private key in PEM format
        pub key_pem: String,
        /// Supported signature schemes
        pub sig_schemes: Vec<u16>,
    }

    /// Certificate without private key (public component only)
    #[derive(Debug, Clone)]
    pub struct CertificatePublic {
        /// Certificate in PEM format
        pub cert_pem: String,
        /// Supported signature schemes
        pub sig_schemes: Vec<u16>,
    }

    // ============================================================================
    // Rust Types Exposed to C++ (Async Contexts)
    // ============================================================================

    // extern "Rust" {
    //     type IoContext;
    //
    //     /// Callback invoked by C++ when async I/O operation completes
    //     fn handle_io_result(context: Box<IoContext>, bytes: usize, error: String);
    // }

    // ============================================================================
    // Opaque C++ Types
    // ============================================================================

    unsafe extern "C++" {
        include!("ffi/certificates_ffi.h");
        include!("ffi/credentials_ffi.h");
        include!("ffi/server_tls_ffi.h");
        include!("ffi/client_tls_ffi.h");

        // Opaque types for C++ objects
        type FizzPrivateKey;
        type FizzCredentialGenerator;
        type FizzServerContext;
        type FizzServerConnection;
        type FizzClientContext;
        type FizzClientConnection;

        // ========================================================================
        // Certificate Loading FFI Functions
        // ========================================================================

        /// Load certificate and private key from PEM strings
        fn load_certificate_from_pem(cert_pem: &str, key_pem: &str) -> Result<CertificateData>;

        /// Load certificate and private key from files
        fn load_certificate_from_file(cert_path: &str, key_path: &str) -> Result<CertificateData>;

        /// Load only the certificate from PEM string (no private key)
        fn load_certificate_public_from_pem(cert_pem: &str) -> Result<CertificatePublic>;

        /// Load only the certificate from file (no private key)
        fn load_certificate_public_from_file(cert_path: &str) -> Result<CertificatePublic>;

        /// Get signature schemes supported by a certificate
        fn get_certificate_sig_schemes(cert_data: &CertificateData) -> Vec<u16>;

        /// Convert certificate to PEM format
        fn certificate_to_pem(cert_data: &CertificateData) -> String;

        /// Load private key from PEM string
        fn load_private_key_from_pem(key_pem: &str) -> Result<UniquePtr<FizzPrivateKey>>;

        /// Generate a new EC P-256 keypair
        fn generate_ec_p256_keypair() -> Result<UniquePtr<FizzPrivateKey>>;

        /// Convert private key to PEM format
        fn private_key_to_pem(key: &FizzPrivateKey) -> String;

        /// Get public key from private key in DER format (hex string)
        fn get_public_key_der(key: &FizzPrivateKey) -> String;

        // ========================================================================
        // Credential Generation FFI Functions
        // ========================================================================

        /// Create a new credential generator from parent cert/key
        fn new_credential_generator(
            parent_cert: &CertificateData,
        ) -> Result<UniquePtr<FizzCredentialGenerator>>;

        /// Generate a delegated credential
        fn generate_delegated_credential(
            generator: &FizzCredentialGenerator,
            service_name: &str,
            valid_seconds: u32,
        ) -> Result<ServiceCredential>;

        /// Self-verify a generated delegated credential
        fn verify_delegated_credential(
            generator: &FizzCredentialGenerator,
            credential: &ServiceCredential,
        ) -> Result<bool>;

        /// Convert delegated credential to PEM format
        fn delegated_credential_to_pem(credential: &ServiceCredential) -> String;

        /// Load delegated credential from PEM format
        fn load_delegated_credential_from_pem(pem: &str) -> Result<ServiceCredential>;

        /// Extract public verification info from credential
        fn get_public_verification_info(credential: &ServiceCredential) -> VerificationInfo;

        /// Convert verification info to JSON string
        fn verification_info_to_json(info: &VerificationInfo) -> String;

        /// Parse verification info from JSON string
        fn verification_info_from_json(json: &str) -> Result<VerificationInfo>;

        // ========================================================================
        // Server TLS FFI Functions
        // ========================================================================

        /// Create a new server TLS context with delegated credentials
        fn new_server_tls_context(
            parent_cert: &CertificatePublic,
            delegated_cred: &ServiceCredential,
        ) -> Result<UniquePtr<FizzServerContext>>;

        /// Set ALPN protocols for server context
        fn server_context_set_alpn_protocols(
            ctx: Pin<&mut FizzServerContext>,
            protocols: Vec<String>,
        );

        /// Accept a new TLS connection from a file descriptor
        fn server_accept_connection(
            ctx: &FizzServerContext,
            fd: i32,
        ) -> Result<UniquePtr<FizzServerConnection>>;

        /// Perform TLS handshake (blocking)
        fn server_connection_handshake(conn: Pin<&mut FizzServerConnection>) -> Result<()>;

        /// Check if connection is open
        fn server_connection_is_open(conn: &FizzServerConnection) -> bool;

        /// Close the connection
        fn server_connection_close(conn: Pin<&mut FizzServerConnection>);

        /// Read data from connection
        fn server_connection_read(
            conn: Pin<&mut FizzServerConnection>,
            buf: &mut [u8],
        ) -> Result<usize>;

        fn server_read_size_hint(conn: Pin<&mut FizzServerConnection>) -> Result<usize>;

        /// True after the peer has closed the TLS stream (`readEOF`); no more app data will arrive.
        fn server_connection_read_eof(conn: &FizzServerConnection) -> bool;

        /// Write data to connection
        fn server_connection_write(
            conn: Pin<&mut FizzServerConnection>,
            buf: &[u8],
        ) -> Result<usize>;





        // ========================================================================
        // Client TLS FFI Functions
        // ========================================================================

        /// Create a new client TLS context with verification info
        fn new_client_tls_context(
            verification_info: &VerificationInfo,
            ca_cert_path: &str,
        ) -> Result<UniquePtr<FizzClientContext>>;

        /// Set ALPN protocols for client context
        fn client_context_set_alpn_protocols(
            ctx: Pin<&mut FizzClientContext>,
            protocols: Vec<String>,
        );

        /// Set SNI hostname for client context
        fn client_context_set_sni(ctx: Pin<&mut FizzClientContext>, hostname: &str);

        /// Connect to a TLS server using a file descriptor
        fn client_connect(
            ctx: &FizzClientContext,
            fd: i32,
            hostname: &str,
        ) -> Result<UniquePtr<FizzClientConnection>>;

        /// Perform TLS handshake (blocking)
        fn client_connection_handshake(conn: Pin<&mut FizzClientConnection>) -> Result<()>;

        /// Check if connection is open
        fn client_connection_is_open(conn: &FizzClientConnection) -> bool;

        /// Close the connection
        fn client_connection_close(conn: Pin<&mut FizzClientConnection>);

        /// Read data from connection
        fn client_connection_read(
            conn: Pin<&mut FizzClientConnection>,
            buf: &mut [u8],
        ) -> Result<usize>;

        fn client_read_size_hint(conn: Pin<&mut FizzClientConnection>) -> Result<usize>;

        fn client_connection_read_eof(conn: &FizzClientConnection) -> bool;

        /// Write data to connection
        fn client_connection_write(
            conn: Pin<&mut FizzClientConnection>,
            buf: &[u8],
        ) -> Result<usize>;

        /// Get peer certificate as PEM string
        fn client_connection_peer_cert(conn: &FizzClientConnection) -> Result<String>;
    }
}

pub fn missing_field<'de, V, E>(field: &'static str) -> Result<V, E>
where
    V: Deserialize<'de>,
    E: serde::de::Error,
{
    struct MissingFieldDeserializer<E>(&'static str, PhantomData<E>);

    impl<'de, E> Deserializer<'de> for MissingFieldDeserializer<E>
    where
        E: serde::de::Error,
    {
        type Error = E;

        fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, E>
        where
            V: Visitor<'de>,
        {
            Err(Self::Error::missing_field(self.0))
        }

        fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, E>
        where
            V: Visitor<'de>,
        {
            visitor.visit_none()
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf unit unit_struct newtype_struct seq tuple
            tuple_struct map struct enum identifier ignored_any
        }
    }

    let deserializer = MissingFieldDeserializer(field, PhantomData);
    Deserialize::deserialize(deserializer)
}


use std::marker::PhantomData;
// Re-export types for use in other modules
pub use ffi::{CertificateData, CertificatePublic, DelegatedCredential, ServiceCredential, VerificationInfo};
use serde::{de::Visitor, Deserialize, Deserializer};
