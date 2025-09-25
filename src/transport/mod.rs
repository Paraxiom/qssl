//! QSSL Transport Layer

use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::{QsslError, QsslResult};
use crate::crypto::{symmetric, SymmetricCipher, HashAlgorithm, hash};

/// QSSL record types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    Handshake = 0x16,
    ApplicationData = 0x17,
    Alert = 0x15,
    ChangeCipherSpec = 0x14,
}

/// QSSL record header
#[derive(Debug, Clone)]
pub struct RecordHeader {
    pub record_type: RecordType,
    pub version: u16,
    pub length: u16,
}

impl RecordHeader {
    pub const SIZE: usize = 5;

    pub fn new(record_type: RecordType, length: u16) -> Self {
        Self {
            record_type,
            version: crate::QSSL_PROTOCOL_VERSION as u16,
            length,
        }
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0] = self.record_type as u8;
        bytes[1..3].copy_from_slice(&self.version.to_be_bytes());
        bytes[3..5].copy_from_slice(&self.length.to_be_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> QsslResult<Self> {
        if bytes.len() < Self::SIZE {
            return Err(QsslError::Protocol("Invalid record header".to_string()));
        }

        let record_type = match bytes[0] {
            0x16 => RecordType::Handshake,
            0x17 => RecordType::ApplicationData,
            0x15 => RecordType::Alert,
            0x14 => RecordType::ChangeCipherSpec,
            _ => return Err(QsslError::Protocol("Unknown record type".to_string())),
        };

        let version = u16::from_be_bytes([bytes[1], bytes[2]]);
        let length = u16::from_be_bytes([bytes[3], bytes[4]]);

        Ok(Self {
            record_type,
            version,
            length,
        })
    }
}

/// QSSL record
#[derive(Debug, Clone)]
pub struct QsslRecord {
    pub header: RecordHeader,
    pub payload: Vec<u8>,
}

impl QsslRecord {
    pub fn new(record_type: RecordType, payload: Vec<u8>) -> Self {
        Self {
            header: RecordHeader::new(record_type, payload.len() as u16),
            payload,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RecordHeader::SIZE + self.payload.len());
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }
}

/// QSSL transport state
pub struct QsslTransport {
    stream: Arc<Mutex<TcpStream>>,
    encryption_key: Arc<Mutex<Option<symmetric::SymmetricKey>>>,
    decryption_key: Arc<Mutex<Option<symmetric::SymmetricKey>>>,
    send_seq: Arc<Mutex<u64>>,
    recv_seq: Arc<Mutex<u64>>,
    cipher: SymmetricCipher,
    hash_algo: HashAlgorithm,
}

impl QsslTransport {
    /// Create new transport from TCP stream
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: Arc::new(Mutex::new(stream)),
            encryption_key: Arc::new(Mutex::new(None)),
            decryption_key: Arc::new(Mutex::new(None)),
            send_seq: Arc::new(Mutex::new(0)),
            recv_seq: Arc::new(Mutex::new(0)),
            cipher: SymmetricCipher::Aes256Gcm,
            hash_algo: HashAlgorithm::Sha384,
        }
    }

    /// Set encryption keys
    pub async fn set_keys(
        &self,
        encryption_key: symmetric::SymmetricKey,
        decryption_key: symmetric::SymmetricKey,
    ) {
        *self.encryption_key.lock().await = Some(encryption_key);
        *self.decryption_key.lock().await = Some(decryption_key);
    }

    /// Send a record (may encrypt if keys are set)
    pub async fn send_record(&self, record: &QsslRecord) -> QsslResult<()> {
        let data = if let Some(ref key) = *self.encryption_key.lock().await {
            // Encrypt the payload
            let mut seq = self.send_seq.lock().await;
            let seq_bytes = seq.to_be_bytes();
            log::debug!("Encrypting record type {:?} with seq={}", record.header.record_type, *seq);
            *seq += 1;

            // AES-GCM adds a 16-byte tag to the ciphertext
            let encrypted_payload_size = 12 + record.payload.len() + 16; // nonce + plaintext + tag

            // Create authenticated data with the header that will be sent
            let encrypted_header = RecordHeader::new(
                record.header.record_type,
                encrypted_payload_size as u16,
            );
            let mut aad = Vec::new();
            aad.extend_from_slice(&encrypted_header.to_bytes());
            aad.extend_from_slice(&seq_bytes);

            let (ciphertext, nonce) = symmetric::encrypt(
                key,
                &record.payload,
                Some(&aad),
            )?;

            // Create encrypted record
            let mut encrypted_payload = Vec::new();
            encrypted_payload.extend_from_slice(&nonce);
            encrypted_payload.extend_from_slice(&ciphertext);

            // Create new record with updated length for encrypted payload
            let encrypted_record = QsslRecord {
                header: RecordHeader::new(
                    record.header.record_type,
                    encrypted_payload.len() as u16,
                ),
                payload: encrypted_payload,
            };
            encrypted_record.to_bytes()
        } else {
            // Send plaintext
            record.to_bytes()
        };

        let mut stream = self.stream.lock().await;
        stream.write_all(&data).await.map_err(QsslError::Io)?;
        stream.flush().await.map_err(QsslError::Io)?;
        Ok(())
    }

    /// Receive a record (may decrypt if keys are set)
    pub async fn recv_record(&self) -> QsslResult<QsslRecord> {
        let mut stream = self.stream.lock().await;

        // Read header
        let mut header_bytes = [0u8; RecordHeader::SIZE];
        stream.read_exact(&mut header_bytes).await.map_err(QsslError::Io)?;
        let header = RecordHeader::from_bytes(&header_bytes)?;

        // Validate length
        if header.length > crate::MAX_RECORD_SIZE as u16 {
            return Err(QsslError::Protocol("Record too large".to_string()));
        }

        // Read payload
        let mut payload = vec![0u8; header.length as usize];
        stream.read_exact(&mut payload).await.map_err(QsslError::Io)?;

        // Decrypt if needed
        let final_payload = if let Some(ref key) = *self.decryption_key.lock().await {
            if payload.len() < 12 {
                return Err(QsslError::Protocol("Invalid encrypted payload".to_string()));
            }

            let nonce = &payload[..12];
            let ciphertext = &payload[12..];

            let mut seq = self.recv_seq.lock().await;
            let seq_bytes = seq.to_be_bytes();
            log::debug!("Decrypting record type {:?} with seq={}", header.record_type, *seq);
            *seq += 1;

            // Create authenticated data (header + sequence)
            let mut aad = Vec::new();
            aad.extend_from_slice(&header_bytes);
            aad.extend_from_slice(&seq_bytes);

            symmetric::decrypt(key, ciphertext, nonce, Some(&aad))?
        } else {
            payload
        };

        Ok(QsslRecord {
            header,
            payload: final_payload,
        })
    }

    /// Send raw bytes (for initial handshake)
    pub async fn send_bytes(&self, data: &[u8]) -> QsslResult<()> {
        let mut stream = self.stream.lock().await;
        stream.write_all(data).await.map_err(QsslError::Io)?;
        stream.flush().await.map_err(QsslError::Io)?;
        Ok(())
    }

    /// Receive raw bytes (for initial handshake)
    pub async fn recv_bytes(&self, buf: &mut [u8]) -> QsslResult<usize> {
        let mut stream = self.stream.lock().await;
        stream.read(buf).await.map_err(QsslError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_header() {
        let header = RecordHeader::new(RecordType::Handshake, 100);
        let bytes = header.to_bytes();
        let parsed = RecordHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.record_type, RecordType::Handshake);
        assert_eq!(parsed.length, 100);
    }

    #[test]
    fn test_record_serialization() {
        let payload = b"Test payload".to_vec();
        let record = QsslRecord::new(RecordType::ApplicationData, payload.clone());
        let bytes = record.to_bytes();

        assert_eq!(&bytes[RecordHeader::SIZE..], &payload[..]);
    }
}