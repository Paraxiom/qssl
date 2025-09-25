//! Integration modules for other protocols

#[cfg(feature = "qssh")]
pub mod qssh;

/// Common integration traits
pub mod traits {
    use async_trait::async_trait;
    use serde::{Serialize, Deserialize};

    /// Transport integration trait
    #[async_trait]
    pub trait TransportIntegration: Send + Sync {
        /// Send data
        async fn send_data(&self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>>;

        /// Receive data
        async fn recv_data(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;

        /// Check if connected
        fn is_connected(&self) -> bool;
    }

    /// Session management trait
    #[async_trait]
    pub trait SessionIntegration: Send + Sync {
        /// Store session
        async fn store_session(&self, id: &[u8], data: &[u8]) -> Result<(), Box<dyn std::error::Error>>;

        /// Retrieve session
        async fn get_session(&self, id: &[u8]) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>>;

        /// Remove session
        async fn remove_session(&self, id: &[u8]) -> Result<bool, Box<dyn std::error::Error>>;
    }

    /// Key management trait
    pub trait KeyIntegration: Send + Sync {
        /// Derive session keys
        fn derive_keys(&self, master_secret: &[u8]) -> Result<SessionKeys, Box<dyn std::error::Error>>;

        /// Export key material
        fn export_keying_material(&self, label: &str, length: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    }

    /// Session keys structure
    #[derive(Debug, Clone)]
    pub struct SessionKeys {
        pub client_write_key: Vec<u8>,
        pub server_write_key: Vec<u8>,
        pub client_write_iv: Vec<u8>,
        pub server_write_iv: Vec<u8>,
    }
}