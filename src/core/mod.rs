//! Core QSSL protocol implementation

use std::sync::Arc;
use tokio::sync::RwLock;
use thiserror::Error;

pub mod handshake;
pub mod state_machine;
pub mod connection;
pub mod context;

pub use connection::QsslConnection;
pub use context::QsslContext;
pub use state_machine::{HandshakeState, ConnectionRole};

/// QSSL Protocol Version
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

impl ProtocolVersion {
    pub const QSSL_1_0: Self = Self { major: 1, minor: 0 };

    pub fn to_wire(&self) -> u16 {
        0x5100 | (self.major as u16) << 4 | (self.minor as u16)
    }

    pub fn from_wire(wire: u16) -> Option<Self> {
        if wire & 0xFF00 != 0x5100 {
            return None;
        }
        Some(Self {
            major: ((wire >> 4) & 0x0F) as u8,
            minor: (wire & 0x0F) as u8,
        })
    }
}

/// QSSL Error types
#[derive(Debug, Error)]
pub enum QsslError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Invalid state transition from {from:?} to {to:?}")]
    InvalidStateTransition {
        from: HandshakeState,
        to: HandshakeState,
    },

    #[error("Unsupported cipher suite: {0:?}")]
    UnsupportedCipherSuite(u16),

    #[error("Certificate validation failed: {0}")]
    CertificateValidation(String),

    #[error("Session not found")]
    SessionNotFound,

    #[error("Alert: level {level}, description {description}")]
    Alert { level: u8, description: u8 },

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Timeout")]
    Timeout,

    #[error("Would block")]
    WouldBlock,

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type QsslResult<T> = Result<T, QsslError>;

/// Alert levels
pub mod alert {
    pub const LEVEL_WARNING: u8 = 1;
    pub const LEVEL_FATAL: u8 = 2;

    pub const CLOSE_NOTIFY: u8 = 0;
    pub const UNEXPECTED_MESSAGE: u8 = 10;
    pub const BAD_RECORD_MAC: u8 = 20;
    pub const HANDSHAKE_FAILURE: u8 = 40;
    pub const BAD_CERTIFICATE: u8 = 42;
    pub const UNSUPPORTED_CERTIFICATE: u8 = 43;
    pub const CERTIFICATE_EXPIRED: u8 = 45;
    pub const UNKNOWN_PQC_ALGORITHM: u8 = 100;
    pub const PQC_SIGNATURE_FAILURE: u8 = 101;
    pub const KEM_FAILURE: u8 = 102;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version() {
        let ver = ProtocolVersion::QSSL_1_0;
        assert_eq!(ver.major, 1);
        assert_eq!(ver.minor, 0);

        let wire = ver.to_wire();
        assert_eq!(wire, 0x5110);

        let parsed = ProtocolVersion::from_wire(wire).unwrap();
        assert_eq!(parsed, ver);
    }
}