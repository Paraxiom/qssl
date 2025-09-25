//! Cryptographic hash functions

use sha2::{Sha256, Sha384, Sha512, Digest};
use sha3::{Sha3_256, Sha3_512};

use crate::QsslResult;
use super::HashAlgorithm;

/// Compute hash of data
pub fn hash(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha3_256 => {
            let mut hasher = Sha3_256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha3_512 => {
            let mut hasher = Sha3_512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
    }
}

/// HMAC-based Key Derivation Function (HKDF)
pub fn hkdf(
    algorithm: HashAlgorithm,
    secret: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> QsslResult<Vec<u8>> {
    use hkdf::Hkdf;

    let output = match algorithm {
        HashAlgorithm::Sha256 => {
            let hk = Hkdf::<Sha256>::new(salt, secret);
            let mut okm = vec![0u8; output_len];
            hk.expand(info, &mut okm)
                .map_err(|e| crate::QsslError::Crypto(format!("HKDF failed: {}", e)))?;
            okm
        }
        HashAlgorithm::Sha384 => {
            let hk = Hkdf::<Sha384>::new(salt, secret);
            let mut okm = vec![0u8; output_len];
            hk.expand(info, &mut okm)
                .map_err(|e| crate::QsslError::Crypto(format!("HKDF failed: {}", e)))?;
            okm
        }
        HashAlgorithm::Sha512 => {
            let hk = Hkdf::<Sha512>::new(salt, secret);
            let mut okm = vec![0u8; output_len];
            hk.expand(info, &mut okm)
                .map_err(|e| crate::QsslError::Crypto(format!("HKDF failed: {}", e)))?;
            okm
        }
        _ => {
            return Err(crate::QsslError::Crypto(
                "HKDF not supported for SHA3".to_string(),
            ))
        }
    };

    Ok(output)
}

/// Derive keys from master secret
pub fn derive_keys(
    algorithm: HashAlgorithm,
    master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> QsslResult<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut salt = Vec::new();
    salt.extend_from_slice(client_random);
    salt.extend_from_slice(server_random);

    // Derive client encryption key
    let client_enc_key = hkdf(
        algorithm,
        master_secret,
        Some(&salt),
        b"client encryption",
        32,
    )?;

    // Derive server encryption key
    let server_enc_key = hkdf(
        algorithm,
        master_secret,
        Some(&salt),
        b"server encryption",
        32,
    )?;

    // Derive client MAC key
    let client_mac_key = hkdf(
        algorithm,
        master_secret,
        Some(&salt),
        b"client mac",
        32,
    )?;

    // Derive server MAC key
    let server_mac_key = hkdf(
        algorithm,
        master_secret,
        Some(&salt),
        b"server mac",
        32,
    )?;

    Ok((client_enc_key, server_enc_key, client_mac_key, server_mac_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithms() {
        let data = b"Test data";

        let sha256 = hash(HashAlgorithm::Sha256, data);
        assert_eq!(sha256.len(), 32);

        let sha384 = hash(HashAlgorithm::Sha384, data);
        assert_eq!(sha384.len(), 48);

        let sha512 = hash(HashAlgorithm::Sha512, data);
        assert_eq!(sha512.len(), 64);
    }

    #[test]
    fn test_key_derivation() {
        let master_secret = b"master secret";
        let client_random = b"client random";
        let server_random = b"server random";

        let (client_enc, server_enc, client_mac, server_mac) =
            derive_keys(HashAlgorithm::Sha256, master_secret, client_random, server_random)
                .unwrap();

        assert_eq!(client_enc.len(), 32);
        assert_eq!(server_enc.len(), 32);
        assert_eq!(client_mac.len(), 32);
        assert_eq!(server_mac.len(), 32);

        // Keys should be different
        assert_ne!(client_enc, server_enc);
        assert_ne!(client_mac, server_mac);
    }
}