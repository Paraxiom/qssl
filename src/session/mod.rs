//! QSSL Session Management

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};

use crate::{QsslError, QsslResult};
use crate::crypto::{CipherSuite, symmetric};

/// Session ID
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SessionId(Vec<u8>);

impl SessionId {
    /// Create new random session ID
    pub fn new() -> Self {
        let mut id = vec![0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut id[..]);
        Self(id)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// QSSL session state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QsslSession {
    /// Session ID
    pub id: Vec<u8>,

    /// Negotiated cipher suite
    pub cipher_suite: CipherSuite,

    /// Master secret
    pub master_secret: Vec<u8>,

    /// Client random
    pub client_random: [u8; 32],

    /// Server random
    pub server_random: [u8; 32],

    /// Creation time
    pub created_at: SystemTime,

    /// Last access time
    pub last_accessed: SystemTime,

    /// Session ticket (for stateless resumption)
    pub ticket: Option<Vec<u8>>,

    /// Early data secret (for 0-RTT)
    pub early_secret: Option<Vec<u8>>,

    /// Max early data size
    pub max_early_data: usize,

    /// ALPN protocol
    pub alpn_protocol: Option<String>,

    /// Server name (SNI)
    pub server_name: Option<String>,
}

impl QsslSession {
    /// Create new session
    pub fn new(
        id: SessionId,
        cipher_suite: CipherSuite,
        master_secret: Vec<u8>,
        client_random: [u8; 32],
        server_random: [u8; 32],
    ) -> Self {
        let now = SystemTime::now();
        Self {
            id: id.0,
            cipher_suite,
            master_secret,
            client_random,
            server_random,
            created_at: now,
            last_accessed: now,
            ticket: None,
            early_secret: None,
            max_early_data: 0,
            alpn_protocol: None,
            server_name: None,
        }
    }

    /// Check if session has expired
    pub fn is_expired(&self, lifetime: Duration) -> bool {
        self.created_at
            .elapsed()
            .map(|elapsed| elapsed > lifetime)
            .unwrap_or(true)
    }

    /// Update last accessed time
    pub fn touch(&mut self) {
        self.last_accessed = SystemTime::now();
    }

    /// Create session ticket
    pub fn create_ticket(&mut self, key: &symmetric::SymmetricKey) -> QsslResult<Vec<u8>> {
        // Serialize session state
        let plaintext = bincode::serialize(self)
            .map_err(|e| QsslError::Protocol(format!("Serialization failed: {}", e)))?;

        // Encrypt with session ticket key
        let (ciphertext, nonce) = symmetric::encrypt(key, &plaintext, None)?;

        // Create ticket: [nonce || ciphertext]
        let mut ticket = Vec::new();
        ticket.extend_from_slice(&nonce);
        ticket.extend_from_slice(&ciphertext);

        self.ticket = Some(ticket.clone());
        Ok(ticket)
    }

    /// Decrypt session ticket
    pub fn from_ticket(ticket: &[u8], key: &symmetric::SymmetricKey) -> QsslResult<Self> {
        if ticket.len() < 12 {
            return Err(QsslError::Protocol("Invalid ticket".to_string()));
        }

        let nonce = &ticket[..12];
        let ciphertext = &ticket[12..];

        // Decrypt
        let plaintext = symmetric::decrypt(key, ciphertext, nonce, None)?;

        // Deserialize
        bincode::deserialize(&plaintext)
            .map_err(|e| QsslError::Protocol(format!("Deserialization failed: {}", e)))
    }
}

/// Session cache for server-side session storage
pub struct SessionCache {
    sessions: Arc<RwLock<HashMap<SessionId, QsslSession>>>,
    max_size: usize,
    lifetime: Duration,
}

impl SessionCache {
    /// Create new session cache
    pub fn new(max_size: usize, lifetime: Duration) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            max_size,
            lifetime,
        }
    }

    /// Store session
    pub async fn store(&self, session: QsslSession) -> QsslResult<()> {
        let id = SessionId::from_bytes(session.id.clone());
        let mut sessions = self.sessions.write().await;

        // Evict expired sessions
        sessions.retain(|_, s| !s.is_expired(self.lifetime));

        // Evict oldest if at capacity
        if sessions.len() >= self.max_size {
            if let Some(oldest_id) = sessions
                .iter()
                .min_by_key(|(_, s)| s.last_accessed)
                .map(|(id, _)| id.clone())
            {
                sessions.remove(&oldest_id);
            }
        }

        sessions.insert(id, session);
        Ok(())
    }

    /// Retrieve session
    pub async fn get(&self, id: &SessionId) -> Option<QsslSession> {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(id) {
            if !session.is_expired(self.lifetime) {
                session.touch();
                return Some(session.clone());
            } else {
                sessions.remove(id);
            }
        }

        None
    }

    /// Remove session
    pub async fn remove(&self, id: &SessionId) -> bool {
        self.sessions.write().await.remove(id).is_some()
    }

    /// Clear all sessions
    pub async fn clear(&self) {
        self.sessions.write().await.clear();
    }

    /// Get number of cached sessions
    pub async fn size(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Clean up expired sessions
    pub async fn cleanup(&self) {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, s| !s.is_expired(self.lifetime));
    }
}

/// Client-side session store
pub struct ClientSessionStore {
    sessions: Arc<RwLock<HashMap<String, QsslSession>>>, // Keyed by server name
}

impl ClientSessionStore {
    /// Create new client session store
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Store session for a server
    pub async fn store(&self, server: String, session: QsslSession) {
        self.sessions.write().await.insert(server, session);
    }

    /// Get session for a server
    pub async fn get(&self, server: &str) -> Option<QsslSession> {
        self.sessions.read().await.get(server).cloned()
    }

    /// Remove session for a server
    pub async fn remove(&self, server: &str) -> bool {
        self.sessions.write().await.remove(server).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id() {
        let id1 = SessionId::new();
        let id2 = SessionId::new();
        assert_ne!(id1, id2);
        assert_eq!(id1.as_bytes().len(), 32);
    }

    #[tokio::test]
    async fn test_session_cache() {
        let cache = SessionCache::new(10, Duration::from_secs(3600));

        let id = SessionId::new();
        let session = QsslSession::new(
            id.clone(),
            CipherSuite::Kyber768Falcon512Aes256,
            vec![0; 48],
            [0; 32],
            [1; 32],
        );

        cache.store(session.clone()).await.unwrap();
        assert_eq!(cache.size().await, 1);

        let retrieved = cache.get(&id).await.unwrap();
        assert_eq!(retrieved.id, session.id);

        cache.remove(&id).await;
        assert_eq!(cache.size().await, 0);
    }

    #[test]
    fn test_session_ticket() {
        let session = QsslSession::new(
            SessionId::new(),
            CipherSuite::Kyber768Falcon512Aes256,
            vec![0; 48],
            [0; 32],
            [1; 32],
        );

        let key = symmetric::SymmetricKey::generate(crate::crypto::SymmetricCipher::Aes256Gcm);
        let mut session_mut = session.clone();
        let ticket = session_mut.create_ticket(&key).unwrap();

        let decrypted = QsslSession::from_ticket(&ticket, &key).unwrap();
        assert_eq!(decrypted.id, session.id);
        assert_eq!(decrypted.master_secret, session.master_secret);
    }
}