//! QSSL Context for configuration

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{QsslResult};
use crate::crypto::{CipherSuite, KemAlgorithm, SignatureAlgorithm};

/// QSSL context configuration
#[derive(Clone)]
pub struct QsslContext {
    /// Supported cipher suites in order of preference
    pub cipher_suites: Vec<CipherSuite>,

    /// Supported KEM algorithms
    pub kem_algorithms: Vec<KemAlgorithm>,

    /// Supported signature algorithms
    pub signature_algorithms: Vec<SignatureAlgorithm>,

    /// Enable session resumption
    pub session_resumption: bool,

    /// Session cache size
    pub session_cache_size: usize,

    /// Enable 0-RTT
    pub zero_rtt: bool,

    /// Max early data size for 0-RTT
    pub max_early_data: usize,

    /// Certificate chain
    pub certificate_chain: Option<Vec<Vec<u8>>>,

    /// Private key
    pub private_key: Option<Vec<u8>>,

    /// Trusted CA certificates
    pub trusted_cas: Vec<Vec<u8>>,

    /// ALPN protocols
    pub alpn_protocols: Vec<String>,

    /// Server name for SNI
    pub server_name: Option<String>,

    /// Verify peer certificate
    pub verify_peer: bool,

    /// Key log callback for debugging
    pub key_log_callback: Option<Arc<dyn Fn(&str) + Send + Sync>>,
}

impl Default for QsslContext {
    fn default() -> Self {
        Self {
            cipher_suites: vec![
                CipherSuite::SphincsKemFalcon512Aes256,  // Primary: Patent-free
                CipherSuite::SphincsKemFalcon512Aes128,
                CipherSuite::SphincsKemFalcon1024Aes256,
                CipherSuite::Kyber768Falcon512Aes256,    // Legacy fallback
                CipherSuite::Kyber512Falcon512Aes128,
                CipherSuite::Kyber1024Falcon1024Aes256,
            ],
            kem_algorithms: vec![
                KemAlgorithm::SphincsKem,  // Primary: Patent-free
                KemAlgorithm::Kyber768,    // Legacy support
                KemAlgorithm::Kyber512,
                KemAlgorithm::Kyber1024,
            ],
            signature_algorithms: vec![
                SignatureAlgorithm::Falcon512,
                SignatureAlgorithm::Falcon1024,
                SignatureAlgorithm::Dilithium3,
            ],
            session_resumption: true,
            session_cache_size: 1000,
            zero_rtt: false,
            max_early_data: 16384,
            certificate_chain: None,
            private_key: None,
            trusted_cas: Vec::new(),
            alpn_protocols: Vec::new(),
            server_name: None,
            verify_peer: true,
            key_log_callback: None,
        }
    }
}

impl QsslContext {
    /// Create a new context with default configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a client context
    pub fn client() -> Self {
        let mut ctx = Self::default();
        ctx.verify_peer = true;
        ctx
    }

    /// Create a server context
    pub fn server() -> Self {
        let mut ctx = Self::default();
        ctx.verify_peer = false; // Optional client auth
        ctx
    }

    /// Set cipher suites
    pub fn set_cipher_suites(&mut self, suites: Vec<CipherSuite>) -> &mut Self {
        self.cipher_suites = suites;
        self
    }

    /// Set certificate chain
    pub fn set_certificate_chain(&mut self, chain: Vec<Vec<u8>>) -> &mut Self {
        self.certificate_chain = Some(chain);
        self
    }

    /// Set private key
    pub fn set_private_key(&mut self, key: Vec<u8>) -> &mut Self {
        self.private_key = Some(key);
        self
    }

    /// Add trusted CA certificate
    pub fn add_trusted_ca(&mut self, ca: Vec<u8>) -> &mut Self {
        self.trusted_cas.push(ca);
        self
    }

    /// Set ALPN protocols
    pub fn set_alpn_protocols(&mut self, protocols: Vec<String>) -> &mut Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Set server name for SNI
    pub fn set_server_name(&mut self, name: String) -> &mut Self {
        self.server_name = Some(name);
        self
    }

    /// Enable/disable peer verification
    pub fn set_verify_peer(&mut self, verify: bool) -> &mut Self {
        self.verify_peer = verify;
        self
    }

    /// Enable session resumption
    pub fn enable_session_resumption(&mut self, cache_size: usize) -> &mut Self {
        self.session_resumption = true;
        self.session_cache_size = cache_size;
        self
    }

    /// Enable 0-RTT
    pub fn enable_zero_rtt(&mut self, max_early_data: usize) -> &mut Self {
        self.zero_rtt = true;
        self.max_early_data = max_early_data;
        self
    }

    /// Set key log callback for debugging
    pub fn set_key_log_callback<F>(&mut self, callback: F) -> &mut Self
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        self.key_log_callback = Some(Arc::new(callback));
        self
    }

    /// Validate context configuration
    pub fn validate(&self) -> QsslResult<()> {
        if self.cipher_suites.is_empty() {
            return Err(crate::QsslError::Protocol(
                "No cipher suites configured".to_string(),
            ));
        }

        if self.kem_algorithms.is_empty() {
            return Err(crate::QsslError::Protocol(
                "No KEM algorithms configured".to_string(),
            ));
        }

        if self.signature_algorithms.is_empty() {
            return Err(crate::QsslError::Protocol(
                "No signature algorithms configured".to_string(),
            ));
        }

        // Server must have certificate and key
        if self.certificate_chain.is_none() && self.private_key.is_some() {
            return Err(crate::QsslError::Protocol(
                "Private key provided without certificate".to_string(),
            ));
        }

        if self.certificate_chain.is_some() && self.private_key.is_none() {
            return Err(crate::QsslError::Protocol(
                "Certificate provided without private key".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_context() {
        let ctx = QsslContext::default();
        assert!(!ctx.cipher_suites.is_empty());
        assert!(ctx.session_resumption);
        assert!(!ctx.zero_rtt);
    }

    #[test]
    fn test_client_context() {
        let ctx = QsslContext::client();
        assert!(ctx.verify_peer);
    }

    #[test]
    fn test_server_context() {
        let ctx = QsslContext::server();
        assert!(!ctx.verify_peer);
    }

    #[test]
    fn test_context_validation() {
        let mut ctx = QsslContext::new();
        assert!(ctx.validate().is_ok());

        ctx.cipher_suites.clear();
        assert!(ctx.validate().is_err());
    }
}