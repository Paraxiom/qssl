//! QSSL Protocol State Machine

use crate::QsslError;

/// Connection role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRole {
    Client,
    Server,
}

/// Handshake states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state
    Init,
    /// Sent/Received ClientHello
    ClientHello,
    /// Sent/Received ServerHello
    ServerHello,
    /// Exchanging certificates
    Certificate,
    /// Key exchange in progress
    KeyExchange,
    /// Verifying certificate
    CertificateVerify,
    /// Handshake finishing
    Finished,
    /// Connection established
    Established,
    /// Connection closed
    Closed,
}

impl HandshakeState {
    /// Check if state transition is valid
    pub fn can_transition_to(&self, next: HandshakeState, role: ConnectionRole) -> bool {
        use HandshakeState::*;

        match (self, next, role) {
            // Client transitions
            (Init, ClientHello, ConnectionRole::Client) => true,
            (ClientHello, ServerHello, ConnectionRole::Client) => true,
            (ServerHello, Certificate, ConnectionRole::Client) => true,
            (Certificate, KeyExchange, ConnectionRole::Client) => true,
            (KeyExchange, CertificateVerify, ConnectionRole::Client) => true,
            (CertificateVerify, Finished, ConnectionRole::Client) => true,
            (Finished, Established, ConnectionRole::Client) => true,

            // Server transitions
            (Init, ClientHello, ConnectionRole::Server) => true,
            (ClientHello, ServerHello, ConnectionRole::Server) => true,
            (ServerHello, Certificate, ConnectionRole::Server) => true,
            (Certificate, KeyExchange, ConnectionRole::Server) => true,
            (KeyExchange, CertificateVerify, ConnectionRole::Server) => true,
            (CertificateVerify, Finished, ConnectionRole::Server) => true,
            (Finished, Established, ConnectionRole::Server) => true,

            // Both can close
            (_, Closed, _) => true,

            // Everything else is invalid
            _ => false,
        }
    }

    /// Attempt to transition to a new state
    pub fn transition_to(
        &mut self,
        next: HandshakeState,
        role: ConnectionRole,
    ) -> Result<(), QsslError> {
        if self.can_transition_to(next, role) {
            log::debug!("State transition: {:?} -> {:?}", self, next);
            *self = next;
            Ok(())
        } else {
            Err(QsslError::InvalidStateTransition {
                from: *self,
                to: next,
            })
        }
    }

    /// Check if handshake is complete
    pub fn is_complete(&self) -> bool {
        matches!(self, HandshakeState::Established)
    }

    /// Check if connection is closed
    pub fn is_closed(&self) -> bool {
        matches!(self, HandshakeState::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_transitions() {
        let mut state = HandshakeState::Init;
        let role = ConnectionRole::Client;

        // Valid client flow
        assert!(state.transition_to(HandshakeState::ClientHello, role).is_ok());
        assert!(state.transition_to(HandshakeState::ServerHello, role).is_ok());
        assert!(state.transition_to(HandshakeState::Certificate, role).is_ok());
        assert!(state.transition_to(HandshakeState::KeyExchange, role).is_ok());
        assert!(state.transition_to(HandshakeState::CertificateVerify, role).is_ok());
        assert!(state.transition_to(HandshakeState::Finished, role).is_ok());
        assert!(state.transition_to(HandshakeState::Established, role).is_ok());
        assert!(state.is_complete());
    }

    #[test]
    fn test_invalid_transition() {
        let mut state = HandshakeState::Init;
        let role = ConnectionRole::Client;

        // Can't jump directly to Established
        assert!(state.transition_to(HandshakeState::Established, role).is_err());
    }
}