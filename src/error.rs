//! Error types for the fizz_rs library.

use thiserror::Error;

/// Result type alias using FizzError
pub type Result<T> = std::result::Result<T, FizzError>;

/// Errors that can occur when using the fizz_rs library
#[derive(Error, Debug)]
pub enum FizzError {
    /// Error loading or parsing a certificate
    #[error("Certificate error: {0}")]
    CertificateError(String),

    /// Error generating or verifying a delegated credential
    #[error("Credential error: {0}")]
    CredentialError(String),

    /// Error during TLS handshake
    #[error("TLS handshake error: {0}")]
    TlsHandshakeError(String),

    /// TLS handshake timed out
    #[error("TLS handshake timed out after {0}ms")]
    HandshakeTimeout(u64),

    /// TLS alert received during handshake
    #[error("TLS alert received: {0} (code: {1})")]
    TlsAlertReceived(String, u8),

    /// Certificate verification failed during handshake
    #[error("Certificate verification failed: {0}")]
    CertificateVerificationFailed(String),

    /// Delegated credential verification failed
    #[error("Delegated credential verification failed: {0}")]
    DelegatedCredentialVerificationFailed(String),

    /// Connection closed unexpectedly
    #[error("Connection closed unexpectedly: {0}")]
    ConnectionClosed(String),

    /// I/O error during TLS operations
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Credential verification failed
    #[error("Verification error: {0}")]
    VerificationError(String),

    /// Error from C++ exception
    #[error("C++ exception: {0}")]
    CxxException(String),

    /// Invalid parameter or argument
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Operation not supported
    #[error("Not supported: {0}")]
    NotSupported(String),

    /// Connection not in expected state
    #[error("Invalid connection state: {0}")]
    InvalidState(String),

    /// Buffer too small for operation
    #[error("Buffer too small: needed {needed} bytes, got {available}")]
    BufferTooSmall { needed: usize, available: usize },
}

impl From<cxx::Exception> for FizzError {
    fn from(e: cxx::Exception) -> Self {
        let msg = e.what().to_string();

        // Parse common error patterns from C++ exceptions for better error reporting
        if msg.contains("Handshake failed") || msg.contains("handshake") {
            // Try to extract specific handshake error details
            if msg.contains("certificate") && msg.contains("verif") {
                return FizzError::CertificateVerificationFailed(msg);
            }
            if msg.contains("delegated credential") || msg.contains("DC") {
                return FizzError::DelegatedCredentialVerificationFailed(msg);
            }
            if msg.contains("timeout") || msg.contains("timed out") {
                // Preserve C++ wording (includes actual duration); avoid a wrong fixed ms value.
                return FizzError::TlsHandshakeError(msg);
            }
            if msg.contains("alert") {
                // TLS alert received
                return FizzError::TlsAlertReceived(msg.clone(), 0);
            }
            return FizzError::TlsHandshakeError(msg);
        }

        if msg.contains("connection closed") || msg.contains("EOF") {
            return FizzError::ConnectionClosed(msg);
        }

        if msg.contains("invalid") || msg.contains("bad") {
            return FizzError::InvalidArgument(msg);
        }

        // Default to CxxException for unknown errors
        FizzError::CxxException(msg)
    }
}

impl FizzError {
    /// Create a handshake error with context
    pub fn handshake(msg: impl Into<String>) -> Self {
        FizzError::TlsHandshakeError(msg.into())
    }

    /// Create a certificate verification error
    pub fn cert_verification(msg: impl Into<String>) -> Self {
        FizzError::CertificateVerificationFailed(msg.into())
    }

    /// Create a delegated credential verification error
    pub fn dc_verification(msg: impl Into<String>) -> Self {
        FizzError::DelegatedCredentialVerificationFailed(msg.into())
    }

    /// Create a connection closed error
    pub fn connection_closed(msg: impl Into<String>) -> Self {
        FizzError::ConnectionClosed(msg.into())
    }

    /// Create an invalid state error
    pub fn invalid_state(msg: impl Into<String>) -> Self {
        FizzError::InvalidState(msg.into())
    }
}
