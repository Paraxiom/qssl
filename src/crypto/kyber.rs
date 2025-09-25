//! Kyber Key Encapsulation Mechanism

use pqcrypto_kyber::{kyber512, kyber768, kyber1024};
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _, SharedSecret as _, Ciphertext as _};
use zeroize::Zeroize;

use crate::{QsslError, QsslResult};
use super::KemAlgorithm;

/// Kyber public key wrapper
pub struct KyberPublicKey {
    pub algorithm: KemAlgorithm,
    pub bytes: Vec<u8>,
}

/// Kyber secret key wrapper (zeroized on drop)
pub struct KyberSecretKey {
    pub algorithm: KemAlgorithm,
    #[allow(dead_code)]
    pub bytes: Vec<u8>,
}

impl Drop for KyberSecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Kyber ciphertext
pub struct KyberCiphertext {
    pub algorithm: KemAlgorithm,
    pub bytes: Vec<u8>,
}

/// Kyber shared secret (zeroized on drop)
pub struct KyberSharedSecret {
    pub bytes: Vec<u8>,
}

impl Drop for KyberSharedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl KyberSharedSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Generate a Kyber keypair
pub fn generate_keypair(algorithm: KemAlgorithm) -> QsslResult<(KyberPublicKey, KyberSecretKey)> {
    let (pk_bytes, sk_bytes) = match algorithm {
        KemAlgorithm::SphincsKem => {
            // Use SPHINCS+ KEM from quantum_native module
            use crate::quantum_native::sphincs_kem::SphincsKem;
            let kem = SphincsKem::new()?;

            // Serialize the SPHINCS+ keys for compatibility
            use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
            (kem.identity_pk.as_bytes().to_vec(),
             kem.identity_sk.as_bytes().to_vec())
        }
        KemAlgorithm::Kyber512 => {
            let (pk, sk) = kyber512::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        }
        KemAlgorithm::Kyber768 => {
            let (pk, sk) = kyber768::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        }
        KemAlgorithm::Kyber1024 => {
            let (pk, sk) = kyber1024::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        }
    };

    Ok((
        KyberPublicKey {
            algorithm,
            bytes: pk_bytes,
        },
        KyberSecretKey {
            algorithm,
            bytes: sk_bytes,
        },
    ))
}

/// Encapsulate a shared secret using a public key
pub fn encapsulate(
    public_key: &KyberPublicKey,
) -> QsslResult<(KyberCiphertext, KyberSharedSecret)> {
    let (ct_bytes, ss_bytes) = match public_key.algorithm {
        KemAlgorithm::SphincsKem => {
            // Use SPHINCS+ KEM encapsulation
            use crate::quantum_native::sphincs_kem::SphincsKem;
            let kem = SphincsKem::new()?;
            let (ciphertext, shared_secret) = kem.encapsulate(&public_key.bytes)?;
            (ciphertext, shared_secret)
        }
        KemAlgorithm::Kyber512 => {
            let pk = kyber512::PublicKey::from_bytes(&public_key.bytes)
                .map_err(|e| QsslError::Crypto(format!("Invalid Kyber512 public key: {:?}", e)))?;
            let (ss, ct) = kyber512::encapsulate(&pk);
            (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
        }
        KemAlgorithm::Kyber768 => {
            let pk = kyber768::PublicKey::from_bytes(&public_key.bytes)
                .map_err(|e| QsslError::Crypto(format!("Invalid Kyber768 public key: {:?}", e)))?;
            let (ss, ct) = kyber768::encapsulate(&pk);
            (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
        }
        KemAlgorithm::Kyber1024 => {
            let pk = kyber1024::PublicKey::from_bytes(&public_key.bytes)
                .map_err(|e| QsslError::Crypto(format!("Invalid Kyber1024 public key: {:?}", e)))?;
            let (ss, ct) = kyber1024::encapsulate(&pk);
            (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
        }
    };

    Ok((
        KyberCiphertext {
            algorithm: public_key.algorithm,
            bytes: ct_bytes,
        },
        KyberSharedSecret { bytes: ss_bytes },
    ))
}

/// Decapsulate a shared secret using a secret key
pub fn decapsulate(
    ciphertext: &KyberCiphertext,
    secret_key: &KyberSecretKey,
) -> QsslResult<KyberSharedSecret> {
    if ciphertext.algorithm != secret_key.algorithm {
        return Err(QsslError::Crypto("Algorithm mismatch".to_string()));
    }

    let ss_bytes = match secret_key.algorithm {
        KemAlgorithm::SphincsKem => {
            // Use SPHINCS+ KEM decapsulation
            use crate::quantum_native::sphincs_kem::SphincsKem;
            use pqcrypto_sphincsplus::sphincsharaka128fsimple as sphincs;
            use pqcrypto_traits::sign::SecretKey as _;

            let sk = sphincs::SecretKey::from_bytes(&secret_key.bytes)
                .map_err(|e| QsslError::Crypto(format!("Invalid SPHINCS+ secret key: {:?}", e)))?;

            // Create KEM with the secret key
            let mut kem = SphincsKem::new()?;
            kem.identity_sk = sk;

            let shared_secret = kem.decapsulate(&ciphertext.bytes, &[])?;
            shared_secret
        }
        KemAlgorithm::Kyber512 => {
            let sk = kyber512::SecretKey::from_bytes(&secret_key.bytes)
                .map_err(|e| QsslError::Crypto(format!("Invalid Kyber512 secret key: {:?}", e)))?;
            let ct = kyber512::Ciphertext::from_bytes(&ciphertext.bytes)
                .map_err(|e| QsslError::Crypto(format!("Invalid Kyber512 ciphertext: {:?}", e)))?;
            let ss = kyber512::decapsulate(&ct, &sk);
            ss.as_bytes().to_vec()
        }
        KemAlgorithm::Kyber768 => {
            let sk = kyber768::SecretKey::from_bytes(&secret_key.bytes)
                .map_err(|e| QsslError::Crypto(format!("Invalid Kyber768 secret key: {:?}", e)))?;
            let ct = kyber768::Ciphertext::from_bytes(&ciphertext.bytes)
                .map_err(|e| QsslError::Crypto(format!("Invalid Kyber768 ciphertext: {:?}", e)))?;
            let ss = kyber768::decapsulate(&ct, &sk);
            ss.as_bytes().to_vec()
        }
        KemAlgorithm::Kyber1024 => {
            let sk = kyber1024::SecretKey::from_bytes(&secret_key.bytes)
                .map_err(|e| QsslError::Crypto(format!("Invalid Kyber1024 secret key: {:?}", e)))?;
            let ct = kyber1024::Ciphertext::from_bytes(&ciphertext.bytes)
                .map_err(|e| QsslError::Crypto(format!("Invalid Kyber1024 ciphertext: {:?}", e)))?;
            let ss = kyber1024::decapsulate(&ct, &sk);
            ss.as_bytes().to_vec()
        }
    };

    Ok(KyberSharedSecret { bytes: ss_bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber768_kem() {
        // Generate keypair
        let (pk, sk) = generate_keypair(KemAlgorithm::Kyber768).unwrap();

        // Encapsulate
        let (ct, ss1) = encapsulate(&pk).unwrap();

        // Decapsulate
        let ss2 = decapsulate(&ct, &sk).unwrap();

        // Shared secrets should match
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }
}