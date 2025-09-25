//! Cryptographic operations for QSSL

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub mod kyber;
pub mod falcon;
pub mod symmetric;
pub mod hash;
pub mod certificate;

use crate::QsslResult;

/// Initialize crypto subsystem
pub fn init() -> QsslResult<()> {
    // Initialize random number generator
    let _ = rand::thread_rng();
    Ok(())
}

/// Cipher suite definitions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum CipherSuite {
    // SPHINCS+ KEM Suites (Patent-free, Quantum-native)
    SphincsKemFalcon512Aes128 = 0x0010,
    SphincsKemFalcon512Aes256 = 0x0011,
    SphincsKemFalcon1024Aes256 = 0x0012,
    SphincsKemSphincs256fAes256 = 0x0013,
    SphincsKemFalcon512ChaCha20 = 0x0014,

    // Legacy Kyber suites (deprecated due to patent concerns)
    Kyber512Falcon512Aes128 = 0x0001,
    Kyber768Falcon512Aes256 = 0x0002,
    Kyber1024Falcon1024Aes256 = 0x0003,
    Kyber512Sphincs128fAes128 = 0x0004,
    Kyber768Sphincs256fAes256 = 0x0005,
    Kyber1024Dilithium3Aes256 = 0x0006,
    Kyber768Falcon512ChaCha20 = 0x0007,
}

impl CipherSuite {
    pub fn kem_algorithm(&self) -> KemAlgorithm {
        use CipherSuite::*;
        match self {
            SphincsKemFalcon512Aes128 | SphincsKemFalcon512Aes256 |
            SphincsKemFalcon1024Aes256 | SphincsKemSphincs256fAes256 |
            SphincsKemFalcon512ChaCha20 => KemAlgorithm::SphincsKem,

            // Legacy Kyber
            Kyber512Falcon512Aes128 | Kyber512Sphincs128fAes128 => KemAlgorithm::Kyber512,
            Kyber768Falcon512Aes256 | Kyber768Sphincs256fAes256 | Kyber768Falcon512ChaCha20 => {
                KemAlgorithm::Kyber768
            }
            Kyber1024Falcon1024Aes256 | Kyber1024Dilithium3Aes256 => KemAlgorithm::Kyber1024,
        }
    }

    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        use CipherSuite::*;
        match self {
            SphincsKemFalcon512Aes128 | SphincsKemFalcon512Aes256 |
            SphincsKemFalcon512ChaCha20 => SignatureAlgorithm::Falcon512,
            SphincsKemFalcon1024Aes256 => SignatureAlgorithm::Falcon1024,
            SphincsKemSphincs256fAes256 => SignatureAlgorithm::Sphincs256f,

            // Legacy
            Kyber512Falcon512Aes128 | Kyber768Falcon512Aes256 | Kyber768Falcon512ChaCha20 => {
                SignatureAlgorithm::Falcon512
            }
            Kyber1024Falcon1024Aes256 => SignatureAlgorithm::Falcon1024,
            Kyber512Sphincs128fAes128 => SignatureAlgorithm::Sphincs128f,
            Kyber768Sphincs256fAes256 => SignatureAlgorithm::Sphincs256f,
            Kyber1024Dilithium3Aes256 => SignatureAlgorithm::Dilithium3,
        }
    }

    pub fn symmetric_cipher(&self) -> SymmetricCipher {
        use CipherSuite::*;
        match self {
            SphincsKemFalcon512Aes128 => SymmetricCipher::Aes128Gcm,
            SphincsKemFalcon512Aes256 | SphincsKemFalcon1024Aes256 |
            SphincsKemSphincs256fAes256 => SymmetricCipher::Aes256Gcm,
            SphincsKemFalcon512ChaCha20 => SymmetricCipher::ChaCha20Poly1305,

            // Legacy
            Kyber512Falcon512Aes128 | Kyber512Sphincs128fAes128 => SymmetricCipher::Aes128Gcm,
            Kyber768Falcon512Aes256 | Kyber1024Falcon1024Aes256 | Kyber768Sphincs256fAes256
            | Kyber1024Dilithium3Aes256 => SymmetricCipher::Aes256Gcm,
            Kyber768Falcon512ChaCha20 => SymmetricCipher::ChaCha20Poly1305,
        }
    }

    pub fn hash_algorithm(&self) -> HashAlgorithm {
        use CipherSuite::*;
        match self {
            SphincsKemFalcon512Aes128 => HashAlgorithm::Sha256,
            SphincsKemFalcon512Aes256 | SphincsKemSphincs256fAes256 |
            SphincsKemFalcon512ChaCha20 => HashAlgorithm::Sha384,
            SphincsKemFalcon1024Aes256 => HashAlgorithm::Sha512,

            // Legacy
            Kyber512Falcon512Aes128 | Kyber512Sphincs128fAes128 => HashAlgorithm::Sha256,
            Kyber768Falcon512Aes256 | Kyber768Sphincs256fAes256 | Kyber768Falcon512ChaCha20 => {
                HashAlgorithm::Sha384
            }
            Kyber1024Falcon1024Aes256 | Kyber1024Dilithium3Aes256 => HashAlgorithm::Sha512,
        }
    }
}

/// KEM algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KemAlgorithm {
    SphincsKem,  // Our patent-free SPHINCS+ based KEM
    Kyber512,    // Deprecated
    Kyber768,    // Deprecated
    Kyber1024,   // Deprecated
}

/// Signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    Falcon512,
    Falcon1024,
    Dilithium2,
    Dilithium3,
    Dilithium5,
    Sphincs128f,
    Sphincs256f,
}

/// Symmetric ciphers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymmetricCipher {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// Hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_512,
}

/// Master secret for key derivation
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MasterSecret {
    secret: Vec<u8>,
}

impl MasterSecret {
    pub fn new(secret: Vec<u8>) -> Self {
        Self { secret }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_suite_algorithms() {
        let suite = CipherSuite::Kyber768Falcon512Aes256;
        assert_eq!(suite.kem_algorithm(), KemAlgorithm::Kyber768);
        assert_eq!(suite.signature_algorithm(), SignatureAlgorithm::Falcon512);
        assert_eq!(suite.symmetric_cipher(), SymmetricCipher::Aes256Gcm);
        assert_eq!(suite.hash_algorithm(), HashAlgorithm::Sha384);
    }
}