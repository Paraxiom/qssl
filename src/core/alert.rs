//! QSSL Alert Protocol

use serde::{Serialize, Deserialize};

/// Alert levels
pub const LEVEL_WARNING: u8 = 1;
pub const LEVEL_FATAL: u8 = 2;

/// Alert descriptions
pub const CLOSE_NOTIFY: u8 = 0;
pub const UNEXPECTED_MESSAGE: u8 = 10;
pub const BAD_RECORD_MAC: u8 = 20;
pub const DECRYPTION_FAILED: u8 = 21;
pub const RECORD_OVERFLOW: u8 = 22;
pub const DECOMPRESSION_FAILURE: u8 = 30;
pub const HANDSHAKE_FAILURE: u8 = 40;
pub const NO_CERTIFICATE: u8 = 41;
pub const BAD_CERTIFICATE: u8 = 42;
pub const UNSUPPORTED_CERTIFICATE: u8 = 43;
pub const CERTIFICATE_REVOKED: u8 = 44;
pub const CERTIFICATE_EXPIRED: u8 = 45;
pub const CERTIFICATE_UNKNOWN: u8 = 46;
pub const ILLEGAL_PARAMETER: u8 = 47;
pub const UNKNOWN_CA: u8 = 48;
pub const ACCESS_DENIED: u8 = 49;
pub const DECODE_ERROR: u8 = 50;
pub const DECRYPT_ERROR: u8 = 51;
pub const PROTOCOL_VERSION: u8 = 70;
pub const INSUFFICIENT_SECURITY: u8 = 71;
pub const INTERNAL_ERROR: u8 = 80;
pub const USER_CANCELED: u8 = 90;
pub const NO_RENEGOTIATION: u8 = 100;
pub const UNSUPPORTED_EXTENSION: u8 = 110;

/// Alert message
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Alert {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

/// Alert level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

/// Alert description
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    DecryptionFailed = 21,
    RecordOverflow = 22,
    DecompressionFailure = 30,
    HandshakeFailure = 40,
    NoCertificate = 41,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    UserCanceled = 90,
    NoRenegotiation = 100,
    UnsupportedExtension = 110,
}

impl Alert {
    pub fn new(level: AlertLevel, description: AlertDescription) -> Self {
        Self { level, description }
    }

    pub fn close_notify() -> Self {
        Self::new(AlertLevel::Warning, AlertDescription::CloseNotify)
    }

    pub fn handshake_failure() -> Self {
        Self::new(AlertLevel::Fatal, AlertDescription::HandshakeFailure)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        vec![self.level as u8, self.description as u8]
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }

        let level = match bytes[0] {
            1 => AlertLevel::Warning,
            2 => AlertLevel::Fatal,
            _ => return None,
        };

        let description = match bytes[1] {
            0 => AlertDescription::CloseNotify,
            10 => AlertDescription::UnexpectedMessage,
            20 => AlertDescription::BadRecordMac,
            21 => AlertDescription::DecryptionFailed,
            22 => AlertDescription::RecordOverflow,
            30 => AlertDescription::DecompressionFailure,
            40 => AlertDescription::HandshakeFailure,
            41 => AlertDescription::NoCertificate,
            42 => AlertDescription::BadCertificate,
            43 => AlertDescription::UnsupportedCertificate,
            44 => AlertDescription::CertificateRevoked,
            45 => AlertDescription::CertificateExpired,
            46 => AlertDescription::CertificateUnknown,
            47 => AlertDescription::IllegalParameter,
            48 => AlertDescription::UnknownCa,
            49 => AlertDescription::AccessDenied,
            50 => AlertDescription::DecodeError,
            51 => AlertDescription::DecryptError,
            70 => AlertDescription::ProtocolVersion,
            71 => AlertDescription::InsufficientSecurity,
            80 => AlertDescription::InternalError,
            90 => AlertDescription::UserCanceled,
            100 => AlertDescription::NoRenegotiation,
            110 => AlertDescription::UnsupportedExtension,
            _ => return None,
        };

        Some(Self::new(level, description))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_serialization() {
        let alert = Alert::close_notify();
        let bytes = alert.to_bytes();
        assert_eq!(bytes, vec![1, 0]);

        let parsed = Alert::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.level, AlertLevel::Warning);
        assert_eq!(parsed.description, AlertDescription::CloseNotify);
    }

    #[test]
    fn test_fatal_alert() {
        let alert = Alert::handshake_failure();
        let bytes = alert.to_bytes();
        assert_eq!(bytes, vec![2, 40]);
    }
}