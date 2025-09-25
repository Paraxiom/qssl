//! QSSL Handshake Protocol

use std::sync::Arc;
use serde::{Serialize, Deserialize};

use crate::{QsslError, QsslResult};
use crate::crypto::{
    CipherSuite, KemAlgorithm, SignatureAlgorithm,
    kyber, symmetric, hash,
    certificate::{QsslCertificate, CertificateBuilder},
};
use crate::transport::{QsslTransport, QsslRecord, RecordType};
use super::{HandshakeState, ConnectionRole, ProtocolVersion};
use pqcrypto_falcon::falcon512;

/// Handshake message types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
}

/// Client Hello message
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientHello {
    pub version: ProtocolVersion,
    pub random: [u8; 32],
    pub session_id: Option<Vec<u8>>,
    pub cipher_suites: Vec<CipherSuite>,
    pub extensions: Vec<Extension>,
}

/// Server Hello message
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerHello {
    pub version: ProtocolVersion,
    pub random: [u8; 32],
    pub session_id: Option<Vec<u8>>,
    pub cipher_suite: CipherSuite,
    pub extensions: Vec<Extension>,
}

/// Certificate message
#[derive(Debug, Serialize, Deserialize)]
pub struct Certificate {
    pub certificate_chain: Vec<Vec<u8>>,
}

/// Key Exchange message
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyExchange {
    pub kem_public_key: Vec<u8>,
    pub kem_ciphertext: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
}

/// Finished message
#[derive(Debug, Serialize, Deserialize)]
pub struct Finished {
    pub verify_data: Vec<u8>,
}

/// Extension types
#[derive(Debug, Serialize, Deserialize)]
pub enum Extension {
    SupportedGroups(Vec<KemAlgorithm>),
    SignatureAlgorithms(Vec<SignatureAlgorithm>),
    KeyShare(Vec<u8>),
    PreSharedKey(Vec<u8>),
    EarlyData(Vec<u8>),
}

/// Handshake context
pub struct HandshakeContext {
    pub role: ConnectionRole,
    pub state: HandshakeState,
    pub transport: Arc<QsslTransport>,
    pub cipher_suite: Option<CipherSuite>,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub master_secret: Option<Vec<u8>>,
    pub transcript: Vec<u8>,
    pub certificate: Option<QsslCertificate>,
    pub peer_certificate: Option<QsslCertificate>,
    pub falcon_sk: Option<falcon512::SecretKey>,
    pub falcon_pk: Option<falcon512::PublicKey>,
    // Store keys but don't activate until handshake complete
    pending_enc_key: Option<symmetric::SymmetricKey>,
    pending_dec_key: Option<symmetric::SymmetricKey>,
}

impl HandshakeContext {
    /// Create new handshake context
    pub fn new(role: ConnectionRole, transport: Arc<QsslTransport>) -> Self {
        let mut client_random = [0u8; 32];
        let mut server_random = [0u8; 32];

        if role == ConnectionRole::Client {
            rand::Rng::fill(&mut rand::thread_rng(), &mut client_random[..]);
        } else {
            rand::Rng::fill(&mut rand::thread_rng(), &mut server_random[..]);
        }

        // Generate Falcon keypair for this connection
        let (falcon_pk, falcon_sk) = falcon512::keypair();

        Self {
            role,
            state: HandshakeState::Init,
            transport,
            cipher_suite: None,
            client_random,
            server_random,
            master_secret: None,
            transcript: Vec::new(),
            certificate: None,
            peer_certificate: None,
            falcon_sk: Some(falcon_sk),
            falcon_pk: Some(falcon_pk),
            pending_enc_key: None,
            pending_dec_key: None,
        }
    }

    /// Perform handshake
    pub async fn handshake(&mut self) -> QsslResult<()> {
        match self.role {
            ConnectionRole::Client => self.client_handshake().await,
            ConnectionRole::Server => self.server_handshake().await,
        }
    }

    /// Client handshake flow
    async fn client_handshake(&mut self) -> QsslResult<()> {
        // Send ClientHello
        self.send_client_hello().await?;
        self.state.transition_to(HandshakeState::ClientHello, self.role)?;

        // Receive ServerHello
        self.recv_server_hello().await?;
        self.state.transition_to(HandshakeState::ServerHello, self.role)?;

        // Receive Certificate
        self.recv_certificate().await?;
        self.state.transition_to(HandshakeState::Certificate, self.role)?;

        // Key Exchange
        self.client_key_exchange().await?;
        self.state.transition_to(HandshakeState::KeyExchange, self.role)?;

        // Certificate Verify
        self.state.transition_to(HandshakeState::CertificateVerify, self.role)?;

        // Finished - send and receive in plaintext
        self.send_finished().await?;
        self.recv_finished().await?;
        self.state.transition_to(HandshakeState::Finished, self.role)?;

        // NOW activate encryption for application data
        self.activate_encryption().await?;

        // Established
        self.state.transition_to(HandshakeState::Established, self.role)?;

        Ok(())
    }

    /// Server handshake flow
    async fn server_handshake(&mut self) -> QsslResult<()> {
        // Receive ClientHello
        self.recv_client_hello().await?;
        self.state.transition_to(HandshakeState::ClientHello, self.role)?;

        // Send ServerHello
        self.send_server_hello().await?;
        self.state.transition_to(HandshakeState::ServerHello, self.role)?;

        // Send Certificate
        self.send_certificate().await?;
        self.state.transition_to(HandshakeState::Certificate, self.role)?;

        // Key Exchange
        self.server_key_exchange().await?;
        self.state.transition_to(HandshakeState::KeyExchange, self.role)?;

        // Certificate Verify
        self.state.transition_to(HandshakeState::CertificateVerify, self.role)?;

        // Finished - receive and send in plaintext
        self.recv_finished().await?;
        self.send_finished().await?;
        self.state.transition_to(HandshakeState::Finished, self.role)?;

        // NOW activate encryption for application data
        self.activate_encryption().await?;

        // Established
        self.state.transition_to(HandshakeState::Established, self.role)?;

        Ok(())
    }

    /// Send ClientHello
    async fn send_client_hello(&mut self) -> QsslResult<()> {
        let hello = ClientHello {
            version: ProtocolVersion::QSSL_1_0,
            random: self.client_random,
            session_id: None,
            cipher_suites: vec![
                CipherSuite::Kyber768Falcon512Aes256,
                CipherSuite::Kyber512Falcon512Aes128,
            ],
            extensions: vec![
                Extension::SupportedGroups(vec![
                    KemAlgorithm::Kyber768,
                    KemAlgorithm::Kyber512,
                ]),
                Extension::SignatureAlgorithms(vec![
                    SignatureAlgorithm::Falcon512,
                    SignatureAlgorithm::Falcon1024,
                ]),
            ],
        };

        let payload = bincode::serialize(&hello)
            .map_err(|e| QsslError::Protocol(format!("Serialization failed: {}", e)))?;

        self.transcript.extend_from_slice(&payload);

        let record = QsslRecord::new(RecordType::Handshake, payload);
        self.transport.send_record(&record).await
    }

    /// Receive ClientHello
    async fn recv_client_hello(&mut self) -> QsslResult<()> {
        let record = self.transport.recv_record().await?;
        if record.header.record_type != RecordType::Handshake {
            return Err(QsslError::Protocol("Expected handshake message".to_string()));
        }

        let hello: ClientHello = bincode::deserialize(&record.payload)
            .map_err(|e| QsslError::Protocol(format!("Deserialization failed: {}", e)))?;

        self.client_random = hello.random;
        self.transcript.extend_from_slice(&record.payload);

        // Select cipher suite
        for suite in hello.cipher_suites {
            if suite == CipherSuite::Kyber768Falcon512Aes256 {
                self.cipher_suite = Some(suite);
                break;
            }
        }

        if self.cipher_suite.is_none() {
            return Err(QsslError::Protocol("No supported cipher suite".to_string()));
        }

        Ok(())
    }

    /// Send ServerHello
    async fn send_server_hello(&mut self) -> QsslResult<()> {
        let hello = ServerHello {
            version: ProtocolVersion::QSSL_1_0,
            random: self.server_random,
            session_id: None,
            cipher_suite: self.cipher_suite.unwrap(),
            extensions: vec![],
        };

        let payload = bincode::serialize(&hello)
            .map_err(|e| QsslError::Protocol(format!("Serialization failed: {}", e)))?;

        self.transcript.extend_from_slice(&payload);

        let record = QsslRecord::new(RecordType::Handshake, payload);
        self.transport.send_record(&record).await
    }

    /// Receive ServerHello
    async fn recv_server_hello(&mut self) -> QsslResult<()> {
        let record = self.transport.recv_record().await?;
        if record.header.record_type != RecordType::Handshake {
            return Err(QsslError::Protocol("Expected handshake message".to_string()));
        }

        let hello: ServerHello = bincode::deserialize(&record.payload)
            .map_err(|e| QsslError::Protocol(format!("Deserialization failed: {}", e)))?;

        self.server_random = hello.random;
        self.cipher_suite = Some(hello.cipher_suite);
        self.transcript.extend_from_slice(&record.payload);

        Ok(())
    }

    /// Send Certificate
    async fn send_certificate(&mut self) -> QsslResult<()> {
        // Generate self-signed certificate for now (in production, would load from config)
        let subject = match self.role {
            ConnectionRole::Server => "CN=qssl.server,O=QSSL,C=US",
            ConnectionRole::Client => "CN=qssl.client,O=QSSL,C=US",
        };

        let cert = CertificateBuilder::new()
            .subject(subject)
            .self_sign(
                self.falcon_sk.as_ref().unwrap(),
                self.falcon_pk.as_ref().unwrap()
            )?;

        // Store our certificate
        self.certificate = Some(cert.clone());

        // Serialize certificate for transmission
        let cert_bytes = bincode::serialize(&cert)
            .map_err(|e| QsslError::Protocol(format!("Certificate serialization failed: {}", e)))?;

        let cert_msg = Certificate {
            certificate_chain: vec![cert_bytes],
        };

        let payload = bincode::serialize(&cert_msg)
            .map_err(|e| QsslError::Protocol(format!("Serialization failed: {}", e)))?;

        self.transcript.extend_from_slice(&payload);

        let record = QsslRecord::new(RecordType::Handshake, payload);
        self.transport.send_record(&record).await
    }

    /// Receive Certificate
    async fn recv_certificate(&mut self) -> QsslResult<()> {
        let record = self.transport.recv_record().await?;
        if record.header.record_type != RecordType::Handshake {
            return Err(QsslError::Protocol("Expected handshake message".to_string()));
        }

        let cert_msg: Certificate = bincode::deserialize(&record.payload)
            .map_err(|e| QsslError::Protocol(format!("Deserialization failed: {}", e)))?;

        self.transcript.extend_from_slice(&record.payload);

        // Deserialize the actual certificate
        if cert_msg.certificate_chain.is_empty() {
            return Err(QsslError::Protocol("Empty certificate chain".to_string()));
        }

        let peer_cert: QsslCertificate = bincode::deserialize(&cert_msg.certificate_chain[0])
            .map_err(|e| QsslError::Protocol(format!("Certificate deserialization failed: {}", e)))?;

        // Verify certificate (self-signed for now)
        if !peer_cert.verify(None)? {
            return Err(QsslError::Protocol("Certificate verification failed".to_string()));
        }

        // Check certificate validity
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if !peer_cert.is_valid_at(now) {
            return Err(QsslError::Protocol("Certificate expired or not yet valid".to_string()));
        }

        // Store peer certificate
        self.peer_certificate = Some(peer_cert);

        Ok(())
    }

    /// Client key exchange
    async fn client_key_exchange(&mut self) -> QsslResult<()> {
        let suite = self.cipher_suite.unwrap();
        let kem_algo = suite.kem_algorithm();

        // Generate ephemeral keypair
        let (public_key, secret_key) = kyber::generate_keypair(kem_algo)?;

        // Send public key to server
        let key_exchange = KeyExchange {
            kem_public_key: public_key.bytes.clone(),
            kem_ciphertext: None,
            signature: None,
        };

        let payload = bincode::serialize(&key_exchange)
            .map_err(|e| QsslError::Protocol(format!("Serialization failed: {}", e)))?;

        self.transcript.extend_from_slice(&payload);

        let record = QsslRecord::new(RecordType::Handshake, payload);
        self.transport.send_record(&record).await?;

        // Receive server's response
        let record = self.transport.recv_record().await?;
        let response: KeyExchange = bincode::deserialize(&record.payload)
            .map_err(|e| QsslError::Protocol(format!("Deserialization failed: {}", e)))?;

        self.transcript.extend_from_slice(&record.payload);

        // Decapsulate to get shared secret
        if let Some(ct_bytes) = response.kem_ciphertext {
            let ciphertext = kyber::KyberCiphertext {
                algorithm: kem_algo,
                bytes: ct_bytes,
            };
            let shared_secret = kyber::decapsulate(&ciphertext, &secret_key)?;

            // Derive master secret
            self.derive_master_secret(&shared_secret.bytes).await?;
        }

        Ok(())
    }

    /// Server key exchange
    async fn server_key_exchange(&mut self) -> QsslResult<()> {
        let record = self.transport.recv_record().await?;
        let key_exchange: KeyExchange = bincode::deserialize(&record.payload)
            .map_err(|e| QsslError::Protocol(format!("Deserialization failed: {}", e)))?;

        self.transcript.extend_from_slice(&record.payload);

        let suite = self.cipher_suite.unwrap();
        let kem_algo = suite.kem_algorithm();

        // Encapsulate with client's public key
        let public_key = kyber::KyberPublicKey {
            algorithm: kem_algo,
            bytes: key_exchange.kem_public_key,
        };
        let (ciphertext, shared_secret) = kyber::encapsulate(&public_key)?;

        // Send ciphertext back
        let response = KeyExchange {
            kem_public_key: vec![],
            kem_ciphertext: Some(ciphertext.bytes),
            signature: None,
        };

        let payload = bincode::serialize(&response)
            .map_err(|e| QsslError::Protocol(format!("Serialization failed: {}", e)))?;

        self.transcript.extend_from_slice(&payload);

        let record = QsslRecord::new(RecordType::Handshake, payload);
        self.transport.send_record(&record).await?;

        // Derive master secret
        self.derive_master_secret(&shared_secret.bytes).await?;

        Ok(())
    }

    /// Derive master secret and keys
    async fn derive_master_secret(&mut self, shared_secret: &[u8]) -> QsslResult<()> {
        let suite = self.cipher_suite.unwrap();
        let hash_algo = suite.hash_algorithm();

        // Compute master secret
        let mut seed = Vec::new();
        seed.extend_from_slice(&self.client_random);
        seed.extend_from_slice(&self.server_random);
        seed.extend_from_slice(&self.transcript);

        let master_secret = hash::hkdf(
            hash_algo,
            shared_secret,
            Some(&seed),
            b"QSSL master secret",
            48,
        )?;

        self.master_secret = Some(master_secret.clone());

        // Derive encryption keys
        let (client_enc, server_enc, _, _) = hash::derive_keys(
            hash_algo,
            &master_secret,
            &self.client_random,
            &self.server_random,
        )?;

        let cipher = suite.symmetric_cipher();

        // Store keys but DON'T activate them yet - wait until after Finished messages
        if self.role == ConnectionRole::Client {
            self.pending_enc_key = Some(symmetric::SymmetricKey::new(cipher, client_enc)?);
            self.pending_dec_key = Some(symmetric::SymmetricKey::new(cipher, server_enc)?);
        } else {
            self.pending_enc_key = Some(symmetric::SymmetricKey::new(cipher, server_enc)?);
            self.pending_dec_key = Some(symmetric::SymmetricKey::new(cipher, client_enc)?);
        }

        Ok(())
    }

    /// Activate encryption after handshake is complete
    async fn activate_encryption(&mut self) -> QsslResult<()> {
        if let (Some(enc_key), Some(dec_key)) = (self.pending_enc_key.take(), self.pending_dec_key.take()) {
            self.transport.set_keys(enc_key, dec_key).await;
            log::debug!("Encryption activated for application data");
        } else {
            return Err(QsslError::Protocol("No pending keys to activate".to_string()));
        }
        Ok(())
    }

    /// Send Finished message
    async fn send_finished(&mut self) -> QsslResult<()> {
        let suite = self.cipher_suite.unwrap();
        let hash_algo = suite.hash_algorithm();

        // Compute verify data
        let verify_data = hash::hash(hash_algo, &self.transcript);

        let finished = Finished { verify_data };

        let payload = bincode::serialize(&finished)
            .map_err(|e| QsslError::Protocol(format!("Serialization failed: {}", e)))?;

        log::debug!("Sending Finished message ({} bytes)", payload.len());

        let record = QsslRecord::new(RecordType::Handshake, payload);
        self.transport.send_record(&record).await
    }

    /// Receive Finished message
    async fn recv_finished(&mut self) -> QsslResult<()> {
        let record = self.transport.recv_record().await?;
        if record.header.record_type != RecordType::Handshake {
            return Err(QsslError::Protocol("Expected handshake message".to_string()));
        }

        let finished: Finished = bincode::deserialize(&record.payload)
            .map_err(|e| QsslError::Protocol(format!("Deserialization failed: {}", e)))?;

        // Verify
        let suite = self.cipher_suite.unwrap();
        let hash_algo = suite.hash_algorithm();
        let expected = hash::hash(hash_algo, &self.transcript);

        if finished.verify_data != expected {
            return Err(QsslError::Protocol("Finished verification failed".to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_message_types() {
        assert_eq!(HandshakeType::ClientHello as u8, 1);
        assert_eq!(HandshakeType::ServerHello as u8, 2);
        assert_eq!(HandshakeType::Finished as u8, 20);
    }
}