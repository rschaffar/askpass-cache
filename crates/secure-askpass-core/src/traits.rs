//! Trait definitions for pluggable components.
//!
//! These traits define the interfaces for:
//! - Password prompting (UI layer)
//! - Socket provisioning (systemd vs manual)
//! - Event monitoring (screen lock, suspend, etc.)
//!
//! By using traits, the daemon can be tested with mock implementations
//! and different UI backends can be swapped at compile time.

use std::future::Future;
use std::pin::Pin;

use tokio::net::UnixListener;

use crate::protocol::ProtocolError;
use crate::types::{PromptConfig, PromptResponse};

/// Error type for prompt operations.
#[derive(Debug, thiserror::Error)]
pub enum PromptError {
    /// User cancelled the prompt.
    #[error("prompt cancelled by user")]
    Cancelled,

    /// Prompt timed out.
    #[error("prompt timed out after {0} seconds")]
    Timeout(u64),

    /// Failed to initialize the UI toolkit.
    #[error("UI initialization failed: {0}")]
    InitializationFailed(String),

    /// Generic UI error.
    #[error("UI error: {0}")]
    UiError(String),
}

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

/// Trait for password prompt implementations.
///
/// This trait abstracts the UI layer, allowing different implementations:
/// - GTK4/libadwaita for GNOME
/// - Pure GTK4 for other desktops
/// - CLI (rpassword) for headless systems
/// - Mock for testing
///
/// # Example (Mock Implementation)
///
/// ```ignore
/// struct MockPrompt {
///     response: Option<PromptResponse>,
/// }
///
/// impl PasswordPrompt for MockPrompt {
///     async fn prompt(&self, config: PromptConfig) -> Result<PromptResponse, PromptError> {
///         self.response.clone().ok_or(PromptError::Cancelled)
///     }
/// }
/// ```
pub trait PasswordPrompt: Send + Sync {
    /// Show a password prompt to the user.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the prompt (text, timeout, etc.)
    ///
    /// # Returns
    ///
    /// The user's response, including the credential and whether to cache it.
    ///
    /// # Errors
    ///
    /// Returns `PromptError::Cancelled` if the user cancels.
    /// Returns `PromptError::Timeout` if the prompt times out.
    fn prompt(
        &self,
        config: PromptConfig,
    ) -> Pin<Box<dyn Future<Output = Result<PromptResponse, PromptError>> + Send + '_>>;
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
    fn prompt_error_display() {
        assert_eq!(
            PromptError::Cancelled.to_string(),
            "prompt cancelled by user"
        );
        assert_eq!(
            PromptError::Timeout(30).to_string(),
            "prompt timed out after 30 seconds"
        );
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

        let response = Response::credential(SecretString::from("pass"), false);
        let line = response.to_json_line().unwrap();
        assert!(line.ends_with('\n'));

        let parsed = Response::parse(line.trim()).unwrap();
        match parsed {
            Response::Credential { value, from_cache } => {
                assert_eq!(value.expose_secret(), "pass");
                assert!(!from_cache);
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
