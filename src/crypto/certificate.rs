//! Post-Quantum Certificate Implementation for QSSL
//!
//! Implements X.509-like certificates with post-quantum signatures

use crate::{QsslError, QsslResult};
use pqcrypto_falcon::falcon512;
use pqcrypto_sphincsplus::sphincsharaka128fsimple as sphincs;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};

/// Post-Quantum Certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QsslCertificate {
    /// Certificate version
    pub version: u8,

    /// Serial number
    pub serial_number: Vec<u8>,

    /// Issuer distinguished name
    pub issuer: String,

    /// Subject distinguished name
    pub subject: String,

    /// Validity period
    pub not_before: u64,  // Unix timestamp
    pub not_after: u64,   // Unix timestamp

    /// Subject's public key
    pub public_key: SubjectPublicKey,

    /// Certificate extensions
    pub extensions: Vec<Extension>,

    /// Signature algorithm
    pub signature_algorithm: SignatureAlgorithm,

    /// Certificate signature
    pub signature: Vec<u8>,
}

/// Subject's public key info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectPublicKey {
    pub algorithm: PublicKeyAlgorithm,
    pub falcon_key: Vec<u8>,
    pub sphincs_key: Option<Vec<u8>>,
}

/// Public key algorithm
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PublicKeyAlgorithm {
    Falcon512,
    SphincsPlus,
    Hybrid,  // Both Falcon and SPHINCS+
}

/// Signature algorithm
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    Falcon512,
    SphincsPlus,
}

/// Certificate extension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extension {
    pub oid: String,
    pub critical: bool,
    pub value: Vec<u8>,
}

/// Certificate builder
pub struct CertificateBuilder {
    cert: QsslCertificate,
}

impl CertificateBuilder {
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            cert: QsslCertificate {
                version: 3,  // X.509 v3 equivalent
                serial_number: Self::generate_serial(),
                issuer: String::new(),
                subject: String::new(),
                not_before: now,
                not_after: now + (365 * 24 * 60 * 60),  // 1 year
                public_key: SubjectPublicKey {
                    algorithm: PublicKeyAlgorithm::Falcon512,
                    falcon_key: Vec::new(),
                    sphincs_key: None,
                },
                extensions: Vec::new(),
                signature_algorithm: SignatureAlgorithm::Falcon512,
                signature: Vec::new(),
            }
        }
    }

    fn generate_serial() -> Vec<u8> {
        let mut serial = vec![0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut serial);
        serial
    }

    pub fn subject(mut self, subject: &str) -> Self {
        self.cert.subject = subject.to_string();
        self
    }

    pub fn issuer(mut self, issuer: &str) -> Self {
        self.cert.issuer = issuer.to_string();
        self
    }

    pub fn validity(mut self, not_before: u64, not_after: u64) -> Self {
        self.cert.not_before = not_before;
        self.cert.not_after = not_after;
        self
    }

    pub fn falcon_public_key(mut self, key: &falcon512::PublicKey) -> Self {
        self.cert.public_key.algorithm = PublicKeyAlgorithm::Falcon512;
        self.cert.public_key.falcon_key = key.as_bytes().to_vec();
        self
    }

    pub fn sphincs_public_key(mut self, key: &sphincs::PublicKey) -> Self {
        self.cert.public_key.algorithm = PublicKeyAlgorithm::SphincsPlus;
        self.cert.public_key.sphincs_key = Some(key.as_bytes().to_vec());
        self
    }

    pub fn hybrid_public_key(mut self, falcon: &falcon512::PublicKey, sphincs: &sphincs::PublicKey) -> Self {
        self.cert.public_key.algorithm = PublicKeyAlgorithm::Hybrid;
        self.cert.public_key.falcon_key = falcon.as_bytes().to_vec();
        self.cert.public_key.sphincs_key = Some(sphincs.as_bytes().to_vec());
        self
    }

    pub fn signature_algorithm(mut self, algo: SignatureAlgorithm) -> Self {
        self.cert.signature_algorithm = algo;
        self
    }

    pub fn add_extension(mut self, oid: &str, critical: bool, value: Vec<u8>) -> Self {
        self.cert.extensions.push(Extension {
            oid: oid.to_string(),
            critical,
            value,
        });
        self
    }

    /// Sign and build the certificate
    pub fn sign_and_build(mut self, signing_key: &SigningKey) -> QsslResult<QsslCertificate> {
        // Compute TBS (To Be Signed) certificate
        let tbs = self.get_tbs_certificate()?;

        // Sign the TBS certificate
        let signature = match self.cert.signature_algorithm {
            SignatureAlgorithm::Falcon512 => {
                match signing_key {
                    SigningKey::Falcon(sk) => {
                        let sig = falcon512::detached_sign(&tbs, sk);
                        sig.as_bytes().to_vec()
                    }
                    _ => return Err(QsslError::Crypto("Signing key doesn't match algorithm".to_string())),
                }
            }
            SignatureAlgorithm::SphincsPlus => {
                match signing_key {
                    SigningKey::Sphincs(sk) => {
                        let sig = sphincs::detached_sign(&tbs, sk);
                        sig.as_bytes().to_vec()
                    }
                    _ => return Err(QsslError::Crypto("Signing key doesn't match algorithm".to_string())),
                }
            }
        };

        self.cert.signature = signature;
        Ok(self.cert)
    }

    /// Build self-signed certificate
    pub fn self_sign(mut self, falcon_sk: &falcon512::SecretKey, falcon_pk: &falcon512::PublicKey) -> QsslResult<QsslCertificate> {
        // Self-signed: issuer = subject
        let subject = self.cert.subject.clone();
        self.cert.issuer = subject;
        self.cert.public_key.algorithm = PublicKeyAlgorithm::Falcon512;
        self.cert.public_key.falcon_key = falcon_pk.as_bytes().to_vec();
        self.cert.signature_algorithm = SignatureAlgorithm::Falcon512;

        self.sign_and_build(&SigningKey::Falcon(falcon_sk))
    }

    fn get_tbs_certificate(&self) -> QsslResult<Vec<u8>> {
        // Create a structure without the signature for signing
        let tbs = TbsCertificate {
            version: self.cert.version,
            serial_number: self.cert.serial_number.clone(),
            issuer: self.cert.issuer.clone(),
            subject: self.cert.subject.clone(),
            not_before: self.cert.not_before,
            not_after: self.cert.not_after,
            public_key: self.cert.public_key.clone(),
            extensions: self.cert.extensions.clone(),
            signature_algorithm: self.cert.signature_algorithm,
        };

        bincode::serialize(&tbs)
            .map_err(|e| QsslError::Crypto(format!("Failed to serialize TBS: {}", e)))
    }
}

/// TBS (To Be Signed) Certificate - everything except signature
#[derive(Serialize, Deserialize)]
struct TbsCertificate {
    version: u8,
    serial_number: Vec<u8>,
    issuer: String,
    subject: String,
    not_before: u64,
    not_after: u64,
    public_key: SubjectPublicKey,
    extensions: Vec<Extension>,
    signature_algorithm: SignatureAlgorithm,
}

/// Signing key wrapper
pub enum SigningKey<'a> {
    Falcon(&'a falcon512::SecretKey),
    Sphincs(&'a sphincs::SecretKey),
}

impl QsslCertificate {
    /// Verify certificate signature
    pub fn verify(&self, issuer_public_key: Option<&VerificationKey>) -> QsslResult<bool> {
        // Get TBS certificate
        let tbs = self.get_tbs()?;

        // For self-signed, use certificate's own public key
        let verify_key = if let Some(key) = issuer_public_key {
            key
        } else {
            // Self-signed verification
            match self.public_key.algorithm {
                PublicKeyAlgorithm::Falcon512 => {
                    let pk = falcon512::PublicKey::from_bytes(&self.public_key.falcon_key)
                        .map_err(|e| QsslError::Crypto(format!("Invalid Falcon key: {:?}", e)))?;
                    return self.verify_with_falcon(&tbs, &pk);
                }
                PublicKeyAlgorithm::SphincsPlus => {
                    if let Some(ref key_bytes) = self.public_key.sphincs_key {
                        let pk = sphincs::PublicKey::from_bytes(key_bytes)
                            .map_err(|e| QsslError::Crypto(format!("Invalid SPHINCS key: {:?}", e)))?;
                        return self.verify_with_sphincs(&tbs, &pk);
                    }
                    return Err(QsslError::Crypto("Missing SPHINCS+ key".to_string()));
                }
                _ => return Err(QsslError::Crypto("Unsupported self-signed algorithm".to_string())),
            }
        };

        // Verify with issuer's key
        match (self.signature_algorithm, verify_key) {
            (SignatureAlgorithm::Falcon512, VerificationKey::Falcon(pk)) => {
                self.verify_with_falcon(&tbs, pk)
            }
            (SignatureAlgorithm::SphincsPlus, VerificationKey::Sphincs(pk)) => {
                self.verify_with_sphincs(&tbs, pk)
            }
            _ => Err(QsslError::Crypto("Algorithm mismatch".to_string())),
        }
    }

    fn verify_with_falcon(&self, tbs: &[u8], pk: &falcon512::PublicKey) -> QsslResult<bool> {
        let sig = falcon512::DetachedSignature::from_bytes(&self.signature)
            .map_err(|e| QsslError::Crypto(format!("Invalid signature: {:?}", e)))?;

        Ok(falcon512::verify_detached_signature(&sig, tbs, pk).is_ok())
    }

    fn verify_with_sphincs(&self, tbs: &[u8], pk: &sphincs::PublicKey) -> QsslResult<bool> {
        let sig = sphincs::DetachedSignature::from_bytes(&self.signature)
            .map_err(|e| QsslError::Crypto(format!("Invalid signature: {:?}", e)))?;

        Ok(sphincs::verify_detached_signature(&sig, tbs, pk).is_ok())
    }

    fn get_tbs(&self) -> QsslResult<Vec<u8>> {
        let tbs = TbsCertificate {
            version: self.version,
            serial_number: self.serial_number.clone(),
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
            not_before: self.not_before,
            not_after: self.not_after,
            public_key: self.public_key.clone(),
            extensions: self.extensions.clone(),
            signature_algorithm: self.signature_algorithm,
        };

        bincode::serialize(&tbs)
            .map_err(|e| QsslError::Crypto(format!("Failed to serialize TBS: {}", e)))
    }

    /// Check if certificate is currently valid
    pub fn is_valid_at(&self, timestamp: u64) -> bool {
        timestamp >= self.not_before && timestamp <= self.not_after
    }

    /// Get certificate fingerprint
    pub fn fingerprint(&self) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        if let Ok(bytes) = bincode::serialize(self) {
            hasher.update(bytes);
        }
        hasher.finalize().to_vec()
    }
}

/// Verification key wrapper
pub enum VerificationKey<'a> {
    Falcon(&'a falcon512::PublicKey),
    Sphincs(&'a sphincs::PublicKey),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_signed_certificate() {
        // Generate Falcon keypair
        let (pk, sk) = falcon512::keypair();

        // Create self-signed certificate
        let cert = CertificateBuilder::new()
            .subject("CN=localhost,O=QSSL Test,C=US")
            .self_sign(&sk, &pk)
            .unwrap();

        // Verify self-signed certificate
        assert!(cert.verify(None).unwrap());

        // Check subject equals issuer
        assert_eq!(cert.subject, cert.issuer);
    }

    #[test]
    fn test_certificate_chain() {
        // Generate CA keypair
        let (ca_pk, ca_sk) = falcon512::keypair();

        // Create CA certificate
        let ca_cert = CertificateBuilder::new()
            .subject("CN=QSSL CA,O=QSSL,C=US")
            .self_sign(&ca_sk, &ca_pk)
            .unwrap();

        // Generate server keypair
        let (server_pk, _server_sk) = falcon512::keypair();

        // Create server certificate signed by CA
        let server_cert = CertificateBuilder::new()
            .subject("CN=server.example.com,O=Example,C=US")
            .issuer("CN=QSSL CA,O=QSSL,C=US")
            .falcon_public_key(&server_pk)
            .sign_and_build(&SigningKey::Falcon(&ca_sk))
            .unwrap();

        // Verify server certificate with CA's public key
        assert!(server_cert.verify(Some(&VerificationKey::Falcon(&ca_pk))).unwrap());
    }
}