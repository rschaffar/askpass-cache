//! Trait definitions for pluggable components.
//!
//! These traits define the interfaces for:
//! - Socket provisioning (systemd vs manual)
//! - Event monitoring (screen lock, suspend, etc.)
//!
//! By using traits, the daemon can be tested with mock implementations.

use std::future::Future;
use std::pin::Pin;

use tokio::net::UnixListener;

use crate::protocol::ProtocolError;

/// Error type for socket provider operations.
#[derive(Debug, thiserror::Error)]
pub enum SocketError {
    /// Failed to bind to the socket.
    #[error("failed to bind socket: {0}")]
    BindFailed(#[source] std::io::Error),

    /// Socket path is invalid.
    #[error("invalid socket path: {0}")]
    InvalidPath(String),

    /// Systemd socket activation failed.
    #[error("systemd socket activation failed: {0}")]
    SystemdActivationFailed(String),

    /// Failed to create the socket directory.
    #[error("failed to create socket directory: {0}")]
    DirectoryCreationFailed(#[source] std::io::Error),
}

/// Error type for event monitor operations.
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    /// Failed to connect to D-Bus.
    #[error("D-Bus connection failed: {0}")]
    DbusConnectionFailed(String),

    /// Failed to subscribe to events.
    #[error("event subscription failed: {0}")]
    SubscriptionFailed(String),
}

/// System events that may trigger cache clearing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemEvent {
    /// Screen was locked.
    ScreenLocked,

    /// Screen was unlocked.
    ScreenUnlocked,

    /// System is about to suspend/sleep.
    Suspend,

    /// System resumed from suspend/sleep.
    Resume,

    /// User session is ending.
    SessionEnding,
}

impl std::fmt::Display for SystemEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SystemEvent::ScreenLocked => write!(f, "screen_locked"),
            SystemEvent::ScreenUnlocked => write!(f, "screen_unlocked"),
            SystemEvent::Suspend => write!(f, "suspend"),
            SystemEvent::Resume => write!(f, "resume"),
            SystemEvent::SessionEnding => write!(f, "session_ending"),
        }
    }
}

/// Trait for socket provider implementations.
///
/// This trait abstracts socket creation, allowing:
/// - Systemd socket activation (production)
/// - Manual socket binding (development/testing)
///
/// # Example (Manual Implementation)
///
/// ```ignore
/// struct ManualSocketProvider {
///     path: PathBuf,
/// }
///
/// impl SocketProvider for ManualSocketProvider {
///     async fn listen(&self) -> Result<UnixListener, SocketError> {
///         UnixListener::bind(&self.path)
///             .map_err(SocketError::BindFailed)
///     }
/// }
/// ```
pub trait SocketProvider: Send + Sync {
    /// Create and return a Unix socket listener.
    ///
    /// For systemd socket activation, this returns the inherited socket.
    /// For manual mode, this creates and binds a new socket.
    ///
    /// # Returns
    ///
    /// A `UnixListener` ready to accept connections.
    fn listen(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<UnixListener, SocketError>> + Send + '_>>;

    /// Return the socket path (for logging/debugging).
    fn socket_path(&self) -> Option<&std::path::Path> {
        None
    }
}

/// Trait for system event monitoring.
///
/// This trait abstracts event sources, allowing:
/// - D-Bus monitoring (screen lock, suspend)
/// - Mock events for testing
/// - No-op for disabled monitoring
///
/// # Example (Mock Implementation)
///
/// ```ignore
/// struct MockEventMonitor {
///     events: VecDeque<SystemEvent>,
/// }
///
/// impl EventMonitor for MockEventMonitor {
///     async fn next_event(&mut self) -> Option<SystemEvent> {
///         self.events.pop_front()
///     }
/// }
/// ```
pub trait EventMonitor: Send + Sync {
    /// Wait for and return the next system event.
    ///
    /// This method should block until an event is available.
    /// Returns `None` if the event source is closed or unavailable.
    fn next_event(&mut self) -> Pin<Box<dyn Future<Output = Option<SystemEvent>> + Send + '_>>;
}

/// A no-op event monitor that never produces events.
///
/// Useful for testing or when event monitoring is disabled.
pub struct NoOpEventMonitor;

impl EventMonitor for NoOpEventMonitor {
    fn next_event(&mut self) -> Pin<Box<dyn Future<Output = Option<SystemEvent>> + Send + '_>> {
        Box::pin(std::future::pending())
    }
}

// Helper trait for parsing protocol messages
impl crate::protocol::Request {
    /// Parse a request from a JSON string.
    pub fn parse(json: &str) -> Result<Self, ProtocolError> {
        serde_json::from_str(json).map_err(ProtocolError::Serialization)
    }

    /// Serialize the request to a JSON string with newline.
    pub fn to_json_line(&self) -> Result<String, ProtocolError> {
        let mut json = serde_json::to_string(self)?;
        json.push('\n');
        Ok(json)
    }
}

impl crate::protocol::Response {
    /// Parse a response from a JSON string.
    pub fn parse(json: &str) -> Result<Self, ProtocolError> {
        serde_json::from_str(json).map_err(ProtocolError::Serialization)
    }

    /// Serialize the response to a JSON string with newline.
    pub fn to_json_line(&self) -> Result<String, ProtocolError> {
        let mut json = serde_json::to_string(self)?;
        json.push('\n');
        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_event_display() {
        assert_eq!(SystemEvent::ScreenLocked.to_string(), "screen_locked");
        assert_eq!(SystemEvent::ScreenUnlocked.to_string(), "screen_unlocked");
        assert_eq!(SystemEvent::Suspend.to_string(), "suspend");
        assert_eq!(SystemEvent::Resume.to_string(), "resume");
        assert_eq!(SystemEvent::SessionEnding.to_string(), "session_ending");
    }

    #[test]
    fn request_parse_and_serialize() {
        use crate::protocol::Request;

        let json = r#"{"type":"get_credential","prompt":"test"}"#;
        let request = Request::parse(json).unwrap();

        match &request {
            Request::GetCredential { prompt, .. } => assert_eq!(prompt, "test"),
            _ => panic!("Wrong request type"),
        }

        let line = request.to_json_line().unwrap();
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn response_parse_and_serialize() {
        use crate::protocol::Response;
        use secrecy::{ExposeSecret, SecretString};

        let response = Response::credential(SecretString::from("pass"));
        let line = response.to_json_line().unwrap();
        assert!(line.ends_with('\n'));

        let parsed = Response::parse(line.trim()).unwrap();
        match parsed {
            Response::Credential { value } => {
                assert_eq!(value.expose_secret(), "pass");
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[tokio::test]
    async fn noop_event_monitor_never_returns() {
        use tokio::time::{timeout, Duration};

        let mut monitor = NoOpEventMonitor;
        let result = timeout(Duration::from_millis(10), monitor.next_event()).await;

        // Should timeout because NoOpEventMonitor never returns
        assert!(result.is_err());
    }
}
