//! QSSH Integration Module
//!
//! Provides QSSL transport layer for QSSH protocol

use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};

use crate::{QsslConnection, QsslContext, QsslResult, QsslError};
use crate::crypto::CipherSuite;

/// QSSH transport wrapper over QSSL connection
pub struct QsshTransport {
    connection: Arc<QsslConnection>,
    context: Arc<QsslContext>,
}

impl QsshTransport {
    /// Create client transport
    pub async fn connect(addr: &str, context: QsslContext) -> QsslResult<Self> {
        let connection = QsslConnection::connect(addr).await?;
        Ok(Self {
            connection: Arc::new(connection),
            context: Arc::new(context),
        })
    }

    /// Create server transport
    pub async fn accept(stream: TcpStream, context: QsslContext) -> QsslResult<Self> {
        let connection = QsslConnection::accept(stream).await?;
        Ok(Self {
            connection: Arc::new(connection),
            context: Arc::new(context),
        })
    }

    /// Send QSSH message
    pub async fn send_message<T: Serialize>(&self, message: &T) -> QsslResult<()> {
        let data = bincode::serialize(message)
            .map_err(|e| QsslError::Protocol(format!("Serialization failed: {}", e)))?;

        self.connection.send(&data).await
    }

    /// Receive QSSH message
    pub async fn recv_message<T: for<'de> Deserialize<'de>>(&self) -> QsslResult<T> {
        let data = self.connection.recv().await?;

        bincode::deserialize(&data)
            .map_err(|e| QsslError::Protocol(format!("Deserialization failed: {}", e)))
    }

    /// Get negotiated cipher suite
    pub fn cipher_suite(&self) -> Option<CipherSuite> {
        self.connection.cipher_suite()
    }

    /// Check if connection is established
    pub async fn is_established(&self) -> bool {
        self.connection.is_established().await
    }

    /// Close connection
    pub async fn close(&self) -> QsslResult<()> {
        self.connection.close().await
    }
}

/// QSSH-specific configuration
#[derive(Debug, Clone)]
pub struct QsshConfig {
    /// Base QSSL context
    pub qssl_context: QsslContext,

    /// QSSH-specific extensions
    pub enable_compression: bool,
    pub enable_multiplexing: bool,
    pub max_packet_size: usize,
}

impl Default for QsshConfig {
    fn default() -> Self {
        let mut context = QsslContext::default();

        // Set QSSH-preferred cipher suites
        context.set_cipher_suites(vec![
            CipherSuite::Kyber768Falcon512Aes256,
            CipherSuite::Kyber512Falcon512Aes128,
        ]);

        // Enable session resumption for better performance
        context.enable_session_resumption(100);

        Self {
            qssl_context: context,
            enable_compression: false,
            enable_multiplexing: true,
            max_packet_size: 32768,
        }
    }
}

/// QSSH protocol messages that can be sent over QSSL
#[derive(Debug, Serialize, Deserialize)]
pub enum QsshMessage {
    /// SSH version exchange
    Version {
        version: String,
        software: String,
        comments: Option<String>,
    },

    /// Key exchange init
    KexInit {
        cookie: [u8; 16],
        kex_algorithms: Vec<String>,
        host_key_algorithms: Vec<String>,
        encryption_algorithms: Vec<String>,
        mac_algorithms: Vec<String>,
        compression_algorithms: Vec<String>,
    },

    /// Authentication request
    AuthRequest {
        username: String,
        service: String,
        method: String,
        data: Vec<u8>,
    },

    /// Channel open
    ChannelOpen {
        channel_type: String,
        sender_channel: u32,
        window_size: u32,
        max_packet_size: u32,
    },

    /// Channel data
    ChannelData {
        channel: u32,
        data: Vec<u8>,
    },

    /// Disconnect
    Disconnect {
        reason_code: u32,
        description: String,
    },
}

/// QSSH session manager using QSSL sessions
pub struct QsshSessionManager {
    qssl_sessions: Arc<RwLock<crate::session::SessionCache>>,
}

impl QsshSessionManager {
    /// Create new session manager
    pub fn new() -> Self {
        Self {
            qssl_sessions: Arc::new(RwLock::new(
                crate::session::SessionCache::new(
                    1000,
                    std::time::Duration::from_secs(3600),
                )
            )),
        }
    }

    /// Store QSSH session
    pub async fn store_session(&self, session_id: &[u8], session_data: Vec<u8>) -> QsslResult<()> {
        // Create a QSSL session wrapper
        let qssl_session = crate::session::QsslSession::new(
            crate::session::SessionId::from_bytes(session_id.to_vec()),
            CipherSuite::Kyber768Falcon512Aes256, // Default for QSSH
            session_data, // Store QSSH session as master secret
            [0; 32], // Placeholder randoms
            [0; 32],
        );

        self.qssl_sessions.read().await.store(qssl_session).await
    }

    /// Retrieve QSSH session
    pub async fn get_session(&self, session_id: &[u8]) -> Option<Vec<u8>> {
        let id = crate::session::SessionId::from_bytes(session_id.to_vec());
        self.qssl_sessions.read().await.get(&id).await
            .map(|session| session.master_secret)
    }

    /// Remove session
    pub async fn remove_session(&self, session_id: &[u8]) -> bool {
        let id = crate::session::SessionId::from_bytes(session_id.to_vec());
        self.qssl_sessions.read().await.remove(&id).await
    }
}

/// Integration test helper
pub async fn test_qssh_over_qssl() -> QsslResult<()> {
    // This function demonstrates how QSSH would use QSSL

    // Create configuration
    let config = QsshConfig::default();

    // In a real scenario:
    // 1. Client connects using QSSL
    // let client = QsshTransport::connect("server:22", config.qssl_context).await?;

    // 2. Send QSSH version
    // let version = QsshMessage::Version {
    //     version: "QSSH-2.0".to_string(),
    //     software: "QSSH_1.0".to_string(),
    //     comments: None,
    // };
    // client.send_message(&version).await?;

    // 3. Receive server version
    // let server_version: QsshMessage = client.recv_message().await?;

    // 4. Continue with QSSH protocol over QSSL transport

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qssh_config() {
        let config = QsshConfig::default();
        assert!(!config.qssl_context.cipher_suites.is_empty());
        assert!(config.enable_multiplexing);
        assert_eq!(config.max_packet_size, 32768);
    }

    #[test]
    fn test_qssh_message_serialization() {
        let msg = QsshMessage::Version {
            version: "QSSH-2.0".to_string(),
            software: "QSSH_1.0".to_string(),
            comments: Some("Test".to_string()),
        };

        let serialized = bincode::serialize(&msg).unwrap();
        let deserialized: QsshMessage = bincode::deserialize(&serialized).unwrap();

        match deserialized {
            QsshMessage::Version { version, .. } => {
                assert_eq!(version, "QSSH-2.0");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[tokio::test]
    async fn test_qssh_session_manager() {
        let manager = QsshSessionManager::new();

        let session_id = b"test_session";
        let session_data = vec![1, 2, 3, 4, 5];

        manager.store_session(session_id, session_data.clone()).await.unwrap();

        let retrieved = manager.get_session(session_id).await.unwrap();
        assert_eq!(retrieved, session_data);

        assert!(manager.remove_session(session_id).await);
        assert!(manager.get_session(session_id).await.is_none());
    }
}