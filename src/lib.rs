//! QSSL - Quantum-Safe Secure Layer
//!
//! A modern, quantum-resistant replacement for TLS/SSL built in Rust.
//!
//! QSSL provides:
//! - Post-quantum key exchange (Kyber)
//! - Post-quantum signatures (Falcon, Dilithium, SPHINCS+)
//! - Memory-safe implementation
//! - Zero-RTT resumption
//! - WebAssembly support

#![cfg_attr(not(feature = "std"), no_std)]

// Core modules
pub mod core;
pub mod crypto;
pub mod transport;
pub mod session;
pub mod integrations;

// TRUE Quantum-Native Protocol (not just TLS with PQC)
pub mod quantum_native;

// FFI for C bindings
// #[cfg(feature = "std")]
// pub mod ffi; // TODO: Implement FFI module

// Re-exports
pub use core::{
    QsslConnection, QsslContext, QsslError, QsslResult,
    HandshakeState, ConnectionRole, ProtocolVersion,
};

pub use crypto::{
    CipherSuite, KemAlgorithm, SignatureAlgorithm,
    SymmetricCipher, HashAlgorithm,
};

pub use transport::{QsslTransport, QsslRecord};
pub use session::{QsslSession, SessionCache};

// Version information
pub const QSSL_VERSION: &str = "0.1.0-alpha";
pub const QSSL_PROTOCOL_VERSION: u16 = 0x5110;  // 'Q' (0x51) + version 1.0 (0x10)

// Default configuration
pub const DEFAULT_CIPHER_SUITE: CipherSuite = CipherSuite::SphincsKemFalcon512Aes256;
pub const MAX_RECORD_SIZE: usize = 16384;
pub const MAX_HANDSHAKE_SIZE: usize = 65536;

/// Initialize QSSL library
pub fn init() -> QsslResult<()> {
    // Initialize crypto providers
    crypto::init()?;

    // Set up logging
    #[cfg(feature = "std")]
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let _ = fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();
    }

    Ok(())
}

/// Get QSSL version string
pub fn version() -> &'static str {
    QSSL_VERSION
}

/// Get protocol version
pub fn protocol_version() -> u16 {
    QSSL_PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(version(), "0.1.0-alpha");
        assert_eq!(protocol_version(), 0x5110);
    }

    #[test]
    fn test_init() {
        assert!(init().is_ok());
    }
}