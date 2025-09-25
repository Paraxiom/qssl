//! QSSL Connection Management

use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use crate::{QsslError, QsslResult};
use crate::crypto::CipherSuite;
use crate::transport::{QsslTransport, QsslRecord, RecordType};
use super::{HandshakeState, ConnectionRole, handshake::HandshakeContext};

/// QSSL connection state
pub struct QsslConnection {
    transport: Arc<QsslTransport>,
    handshake_state: Arc<RwLock<HandshakeState>>,
    role: ConnectionRole,
    cipher_suite: Option<CipherSuite>,
    is_resumed: bool,
    session_id: Option<Vec<u8>>,
}

impl QsslConnection {
    /// Create new QSSL connection as client
    pub async fn connect(addr: &str) -> QsslResult<Self> {
        let stream = TcpStream::connect(addr).await.map_err(QsslError::Io)?;
        let transport = Arc::new(QsslTransport::new(stream));

        let mut conn = Self {
            transport: transport.clone(),
            handshake_state: Arc::new(RwLock::new(HandshakeState::Init)),
            role: ConnectionRole::Client,
            cipher_suite: None,
            is_resumed: false,
            session_id: None,
        };

        // Perform handshake
        let mut handshake = HandshakeContext::new(ConnectionRole::Client, transport);
        handshake.handshake().await?;

        *conn.handshake_state.write().await = HandshakeState::Established;
        conn.cipher_suite = handshake.cipher_suite;

        Ok(conn)
    }

    /// Create new QSSL connection from accepted TCP stream
    pub async fn accept(stream: TcpStream) -> QsslResult<Self> {
        let transport = Arc::new(QsslTransport::new(stream));

        let mut conn = Self {
            transport: transport.clone(),
            handshake_state: Arc::new(RwLock::new(HandshakeState::Init)),
            role: ConnectionRole::Server,
            cipher_suite: None,
            is_resumed: false,
            session_id: None,
        };

        // Perform handshake
        let mut handshake = HandshakeContext::new(ConnectionRole::Server, transport);
        handshake.handshake().await?;

        *conn.handshake_state.write().await = HandshakeState::Established;
        conn.cipher_suite = handshake.cipher_suite;

        Ok(conn)
    }

    /// Send application data
    pub async fn send(&self, data: &[u8]) -> QsslResult<()> {
        let state = *self.handshake_state.read().await;
        if !state.is_complete() {
            return Err(QsslError::Protocol("Handshake not complete".to_string()));
        }

        let record = QsslRecord::new(RecordType::ApplicationData, data.to_vec());
        self.transport.send_record(&record).await
    }

    /// Receive application data
    pub async fn recv(&self) -> QsslResult<Vec<u8>> {
        let state = *self.handshake_state.read().await;
        if !state.is_complete() {
            return Err(QsslError::Protocol("Handshake not complete".to_string()));
        }

        let record = self.transport.recv_record().await?;
        if record.header.record_type != RecordType::ApplicationData {
            return Err(QsslError::Protocol("Expected application data".to_string()));
        }

        Ok(record.payload)
    }

    /// Close connection
    pub async fn close(&self) -> QsslResult<()> {
        // Send close alert
        let alert = vec![
            crate::core::alert::LEVEL_WARNING,
            crate::core::alert::CLOSE_NOTIFY,
        ];

        let record = QsslRecord::new(RecordType::Alert, alert);
        self.transport.send_record(&record).await?;

        *self.handshake_state.write().await = HandshakeState::Closed;
        Ok(())
    }

    /// Check if connection is established
    pub async fn is_established(&self) -> bool {
        self.handshake_state.read().await.is_complete()
    }

    /// Get connection role
    pub fn role(&self) -> ConnectionRole {
        self.role
    }

    /// Get negotiated cipher suite
    pub fn cipher_suite(&self) -> Option<CipherSuite> {
        self.cipher_suite
    }

    /// Check if session was resumed
    pub fn is_resumed(&self) -> bool {
        self.is_resumed
    }

    /// Get session ID
    pub fn session_id(&self) -> Option<&[u8]> {
        self.session_id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_role() {
        // This is a placeholder test
        assert_eq!(ConnectionRole::Client, ConnectionRole::Client);
        assert_eq!(ConnectionRole::Server, ConnectionRole::Server);
    }
}