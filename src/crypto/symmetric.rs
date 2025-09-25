//! Symmetric encryption operations

use aes_gcm::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    Aes128Gcm, Aes256Gcm, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;
use rand::Rng;
use zeroize::Zeroize;

use crate::{QsslError, QsslResult};
use super::SymmetricCipher;

/// Symmetric key wrapper (zeroized on drop)
pub struct SymmetricKey {
    cipher: SymmetricCipher,
    bytes: Vec<u8>,
}

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl SymmetricKey {
    pub fn new(cipher: SymmetricCipher, bytes: Vec<u8>) -> QsslResult<Self> {
        let expected_len = match cipher {
            SymmetricCipher::Aes128Gcm => 16,
            SymmetricCipher::Aes256Gcm => 32,
            SymmetricCipher::ChaCha20Poly1305 => 32,
        };

        if bytes.len() != expected_len {
            return Err(QsslError::Crypto(format!(
                "Invalid key length: expected {}, got {}",
                expected_len,
                bytes.len()
            )));
        }

        Ok(Self { cipher, bytes })
    }

    pub fn generate(cipher: SymmetricCipher) -> Self {
        let key_len = match cipher {
            SymmetricCipher::Aes128Gcm => 16,
            SymmetricCipher::Aes256Gcm => 32,
            SymmetricCipher::ChaCha20Poly1305 => 32,
        };

        let mut bytes = vec![0u8; key_len];
        rand::thread_rng().fill(&mut bytes[..]);

        Self { cipher, bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Encrypt data with authenticated encryption
pub fn encrypt(
    key: &SymmetricKey,
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> QsslResult<(Vec<u8>, Vec<u8>)> {
    let mut nonce = vec![0u8; 12];
    rand::thread_rng().fill(&mut nonce[..]);

    let ciphertext = match key.cipher {
        SymmetricCipher::Aes128Gcm => {
            let cipher = Aes128Gcm::new(GenericArray::from_slice(&key.bytes));
            let nonce_array = Nonce::from_slice(&nonce);

            if let Some(aad) = associated_data {
                cipher.encrypt(nonce_array, aead::Payload {
                    msg: plaintext,
                    aad,
                }).map_err(|e| QsslError::Crypto(format!("AES-128-GCM encryption failed: {}", e)))?
            } else {
                cipher.encrypt(nonce_array, plaintext)
                    .map_err(|e| QsslError::Crypto(format!("AES-128-GCM encryption failed: {}", e)))?
            }
        }
        SymmetricCipher::Aes256Gcm => {
            let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.bytes));
            let nonce_array = Nonce::from_slice(&nonce);

            if let Some(aad) = associated_data {
                cipher.encrypt(nonce_array, aead::Payload {
                    msg: plaintext,
                    aad,
                }).map_err(|e| QsslError::Crypto(format!("AES-256-GCM encryption failed: {}", e)))?
            } else {
                cipher.encrypt(nonce_array, plaintext)
                    .map_err(|e| QsslError::Crypto(format!("AES-256-GCM encryption failed: {}", e)))?
            }
        }
        SymmetricCipher::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key.bytes));
            let nonce_array = GenericArray::from_slice(&nonce);

            if let Some(aad) = associated_data {
                cipher.encrypt(nonce_array, aead::Payload {
                    msg: plaintext,
                    aad,
                }).map_err(|e| QsslError::Crypto(format!("ChaCha20-Poly1305 encryption failed: {}", e)))?
            } else {
                cipher.encrypt(nonce_array, plaintext)
                    .map_err(|e| QsslError::Crypto(format!("ChaCha20-Poly1305 encryption failed: {}", e)))?
            }
        }
    };

    Ok((ciphertext, nonce))
}

/// Decrypt data with authenticated encryption
pub fn decrypt(
    key: &SymmetricKey,
    ciphertext: &[u8],
    nonce: &[u8],
    associated_data: Option<&[u8]>,
) -> QsslResult<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(QsslError::Crypto("Invalid nonce length".to_string()));
    }

    let plaintext = match key.cipher {
        SymmetricCipher::Aes128Gcm => {
            let cipher = Aes128Gcm::new(GenericArray::from_slice(&key.bytes));
            let nonce_array = Nonce::from_slice(nonce);

            if let Some(aad) = associated_data {
                cipher.decrypt(nonce_array, aead::Payload {
                    msg: ciphertext,
                    aad,
                }).map_err(|e| QsslError::Crypto(format!("AES-128-GCM decryption failed: {}", e)))?
            } else {
                cipher.decrypt(nonce_array, ciphertext)
                    .map_err(|e| QsslError::Crypto(format!("AES-128-GCM decryption failed: {}", e)))?
            }
        }
        SymmetricCipher::Aes256Gcm => {
            let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.bytes));
            let nonce_array = Nonce::from_slice(nonce);

            if let Some(aad) = associated_data {
                cipher.decrypt(nonce_array, aead::Payload {
                    msg: ciphertext,
                    aad,
                }).map_err(|e| QsslError::Crypto(format!("AES-256-GCM decryption failed: {}", e)))?
            } else {
                cipher.decrypt(nonce_array, ciphertext)
                    .map_err(|e| QsslError::Crypto(format!("AES-256-GCM decryption failed: {}", e)))?
            }
        }
        SymmetricCipher::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key.bytes));
            let nonce_array = GenericArray::from_slice(nonce);

            if let Some(aad) = associated_data {
                cipher.decrypt(nonce_array, aead::Payload {
                    msg: ciphertext,
                    aad,
                }).map_err(|e| QsslError::Crypto(format!("ChaCha20-Poly1305 decryption failed: {}", e)))?
            } else {
                cipher.decrypt(nonce_array, ciphertext)
                    .map_err(|e| QsslError::Crypto(format!("ChaCha20-Poly1305 decryption failed: {}", e)))?
            }
        }
    };

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_gcm_roundtrip() {
        let key = SymmetricKey::generate(SymmetricCipher::Aes256Gcm);
        let plaintext = b"Hello, quantum world!";
        let aad = b"Additional data";

        let (ciphertext, nonce) = encrypt(&key, plaintext, Some(aad)).unwrap();
        let decrypted = decrypt(&key, &ciphertext, &nonce, Some(aad)).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let key = SymmetricKey::generate(SymmetricCipher::ChaCha20Poly1305);
        let plaintext = b"Quantum-safe data";

        let (ciphertext, nonce) = encrypt(&key, plaintext, None).unwrap();
        let decrypted = decrypt(&key, &ciphertext, &nonce, None).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }
}