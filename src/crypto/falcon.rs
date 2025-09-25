//! Falcon Digital Signature Algorithm

use pqcrypto_falcon::{falcon512, falcon1024};
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, SignedMessage as _, DetachedSignature as _};
use zeroize::Zeroize;

use crate::{QsslError, QsslResult};
use super::SignatureAlgorithm;

/// Falcon public key wrapper
pub struct FalconPublicKey {
    algorithm: SignatureAlgorithm,
    bytes: Vec<u8>,
}

impl FalconPublicKey {
    pub fn from_bytes(algorithm: SignatureAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Falcon secret key wrapper (zeroized on drop)
pub struct FalconSecretKey {
    algorithm: SignatureAlgorithm,
    bytes: Vec<u8>,
}

impl Drop for FalconSecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl FalconSecretKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Falcon signature
pub struct FalconSignature {
    algorithm: SignatureAlgorithm,
    bytes: Vec<u8>,
}

impl FalconSignature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Generate a Falcon keypair
pub fn generate_keypair(algorithm: SignatureAlgorithm) -> QsslResult<(FalconPublicKey, FalconSecretKey)> {
    let (pk_bytes, sk_bytes) = match algorithm {
        SignatureAlgorithm::Falcon512 => {
            let (pk, sk) = falcon512::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        }
        SignatureAlgorithm::Falcon1024 => {
            let (pk, sk) = falcon1024::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        }
        _ => return Err(QsslError::Crypto("Unsupported algorithm".to_string())),
    };

    Ok((
        FalconPublicKey {
            algorithm,
            bytes: pk_bytes,
        },
        FalconSecretKey {
            algorithm,
            bytes: sk_bytes,
        },
    ))
}

/// Sign a message with a secret key
pub fn sign(
    message: &[u8],
    secret_key: &FalconSecretKey,
) -> QsslResult<FalconSignature> {
    let sig_bytes = match secret_key.algorithm {
        SignatureAlgorithm::Falcon512 => {
            let sk = falcon512::SecretKey::from_bytes(&secret_key.bytes)
                .map_err(|e| QsslError::Crypto(format!("Invalid Falcon512 secret key: {:?}", e)))?;
            let sig = falcon512::detached_sign(message, &sk);
            sig.as_bytes().to_vec()
        }
        SignatureAlgorithm::Falcon1024 => {
            let sk = falcon1024::SecretKey::from_bytes(&secret_key.bytes)
                .map_err(|e| QsslError::Crypto(format!("Invalid Falcon1024 secret key: {:?}", e)))?;
            let sig = falcon1024::detached_sign(message, &sk);
            sig.as_bytes().to_vec()
        }
        _ => return Err(QsslError::Crypto("Unsupported algorithm".to_string())),
    };

    Ok(FalconSignature {
        algorithm: secret_key.algorithm,
        bytes: sig_bytes,
    })
}

/// Verify a signature with a public key
pub fn verify(
    message: &[u8],
    signature: &FalconSignature,
    public_key: &FalconPublicKey,
) -> QsslResult<bool> {
    if signature.algorithm != public_key.algorithm {
        return Err(QsslError::Crypto("Algorithm mismatch".to_string()));
    }

    let result = match public_key.algorithm {
        SignatureAlgorithm::Falcon512 => {
            let pk = falcon512::PublicKey::from_bytes(&public_key.bytes)
                .map_err(|e| QsslError::Crypto(format!("Invalid Falcon512 public key: {:?}", e)))?;
            let sig = falcon512::DetachedSignature::from_bytes(&signature.bytes)
                .map_err(|e| QsslError::Crypto(format!("Invalid Falcon512 signature: {:?}", e)))?;
            falcon512::verify_detached_signature(&sig, message, &pk).is_ok()
        }
        SignatureAlgorithm::Falcon1024 => {
            let pk = falcon1024::PublicKey::from_bytes(&public_key.bytes)
                .map_err(|e| QsslError::Crypto(format!("Invalid Falcon1024 public key: {:?}", e)))?;
            let sig = falcon1024::DetachedSignature::from_bytes(&signature.bytes)
                .map_err(|e| QsslError::Crypto(format!("Invalid Falcon1024 signature: {:?}", e)))?;
            falcon1024::verify_detached_signature(&sig, message, &pk).is_ok()
        }
        _ => return Err(QsslError::Crypto("Unsupported algorithm".to_string())),
    };

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_falcon512_sign_verify() {
        let (pk, sk) = generate_keypair(SignatureAlgorithm::Falcon512).unwrap();

        let message = b"Test message for Falcon512";
        let signature = sign(message, &sk).unwrap();

        assert!(verify(message, &signature, &pk).unwrap());
        assert!(!verify(b"Wrong message", &signature, &pk).unwrap());
    }
}