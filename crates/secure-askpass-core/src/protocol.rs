//! Protocol types for client-daemon communication.
//!
//! The secure-askpass protocol uses JSON over Unix sockets with newline-delimited messages.
//! This module defines the request and response types for the protocol.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::CacheType;

/// A request from the client to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Request a credential (show prompt or return from cache).
    GetCredential {
        /// The prompt text to display to the user.
        prompt: String,

        /// The cache ID for this credential.
        /// Use "auto" to auto-detect from the prompt text.
        #[serde(default = "default_cache_id")]
        cache_id: String,

        /// The type of credential (optional, auto-detected if not provided).
        #[serde(default)]
        cache_type: Option<CacheType>,

        /// TTL override in seconds (optional, uses cache type default if not provided).
        #[serde(default)]
        ttl: Option<u64>,

        /// Whether to use/store cached credentials (default: true).
        #[serde(default = "default_true")]
        allow_cache: bool,

        /// Whether to echo input (default: false for passwords).
        #[serde(default)]
        echo: bool,
    },

    /// Clear cached credentials.
    ClearCache {
        /// The cache ID to clear.
        /// Use "all" to clear all entries, or a specific cache ID.
        cache_id: String,

        /// Optionally clear only entries of a specific type.
        #[serde(default)]
        cache_type: Option<CacheType>,
    },

    /// Ping the daemon (health check).
    Ping,
}

fn default_cache_id() -> String {
    "auto".to_string()
}

fn default_true() -> bool {
    true
}

/// A response from the daemon to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// A credential response.
    Credential {
        /// The credential value.
        /// Note: This is serialized as a plain string in JSON for IPC.
        #[serde(
            serialize_with = "serialize_secret",
            deserialize_with = "deserialize_secret"
        )]
        value: SecretString,

        /// Whether this credential came from the cache.
        from_cache: bool,
    },

    /// An error response.
    Error {
        /// The error code.
        code: ErrorCode,

        /// A human-readable error message.
        message: String,
    },

    /// Confirmation that the cache was cleared.
    CacheCleared {
        /// Number of entries removed.
        count: usize,
    },

    /// Response to a ping request.
    Pong,
}

/// Error codes for protocol errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// User cancelled the prompt.
    Cancelled,

    /// Prompt timed out.
    Timeout,

    /// Invalid request format.
    InvalidRequest,

    /// Internal daemon error.
    InternalError,

    /// Daemon is shutting down.
    ShuttingDown,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCode::Cancelled => write!(f, "cancelled"),
            ErrorCode::Timeout => write!(f, "timeout"),
            ErrorCode::InvalidRequest => write!(f, "invalid_request"),
            ErrorCode::InternalError => write!(f, "internal_error"),
            ErrorCode::ShuttingDown => write!(f, "shutting_down"),
        }
    }
}

/// Errors that can occur during protocol operations.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Failed to serialize a message.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Failed to read/write to the socket.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Received an invalid message.
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// Connection closed unexpectedly.
    #[error("connection closed")]
    ConnectionClosed,
}

// Custom serialization for SecretString - exposes the secret for IPC
fn serialize_secret<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use secrecy::ExposeSecret;
    serializer.serialize_str(secret.expose_secret())
}

fn deserialize_secret<'de, D>(deserializer: D) -> Result<SecretString, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(SecretString::from(s))
}

impl Response {
    /// Create a credential response.
    pub fn credential(value: SecretString, from_cache: bool) -> Self {
        Response::Credential { value, from_cache }
    }

    /// Create an error response.
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Response::Error {
            code,
            message: message.into(),
        }
    }

    /// Create a cache cleared response.
    pub fn cache_cleared(count: usize) -> Self {
        Response::CacheCleared { count }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn request_get_credential_serde_roundtrip() {
        let request = Request::GetCredential {
            prompt: "Enter PIN for key".to_string(),
            cache_id: "ssh-fido:SHA256:abc".to_string(),
            cache_type: Some(CacheType::Ssh),
            ttl: Some(3600),
            allow_cache: true,
            echo: false,
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();

        match parsed {
            Request::GetCredential {
                prompt,
                cache_id,
                cache_type,
                ttl,
                allow_cache,
                echo,
            } => {
                assert_eq!(prompt, "Enter PIN for key");
                assert_eq!(cache_id, "ssh-fido:SHA256:abc");
                assert_eq!(cache_type, Some(CacheType::Ssh));
                assert_eq!(ttl, Some(3600));
                assert!(allow_cache);
                assert!(!echo);
            }
            _ => panic!("Wrong request type"),
        }
    }

    #[test]
    fn request_get_credential_minimal() {
        // Test with only required field
        let json = r#"{"type": "get_credential", "prompt": "Enter password"}"#;
        let request: Request = serde_json::from_str(json).unwrap();

        match request {
            Request::GetCredential {
                prompt,
                cache_id,
                cache_type,
                ttl,
                allow_cache,
                echo,
            } => {
                assert_eq!(prompt, "Enter password");
                assert_eq!(cache_id, "auto");
                assert_eq!(cache_type, None);
                assert_eq!(ttl, None);
                assert!(allow_cache); // default true
                assert!(!echo); // default false
            }
            _ => panic!("Wrong request type"),
        }
    }

    #[test]
    fn request_clear_cache_serde_roundtrip() {
        let request = Request::ClearCache {
            cache_id: "all".to_string(),
            cache_type: Some(CacheType::Git),
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();

        match parsed {
            Request::ClearCache {
                cache_id,
                cache_type,
            } => {
                assert_eq!(cache_id, "all");
                assert_eq!(cache_type, Some(CacheType::Git));
            }
            _ => panic!("Wrong request type"),
        }
    }

    #[test]
    fn request_ping_serde_roundtrip() {
        let request = Request::Ping;
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(json, r#"{"type":"ping"}"#);

        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Request::Ping));
    }

    #[test]
    fn response_credential_serde_roundtrip() {
        let response = Response::credential(SecretString::from("secret123"), true);

        let json = serde_json::to_string(&response).unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();

        match parsed {
            Response::Credential { value, from_cache } => {
                assert_eq!(value.expose_secret(), "secret123");
                assert!(from_cache);
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn response_error_serde_roundtrip() {
        let response = Response::error(ErrorCode::Cancelled, "User cancelled");

        let json = serde_json::to_string(&response).unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();

        match parsed {
            Response::Error { code, message } => {
                assert_eq!(code, ErrorCode::Cancelled);
                assert_eq!(message, "User cancelled");
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn response_cache_cleared_serde_roundtrip() {
        let response = Response::cache_cleared(5);

        let json = serde_json::to_string(&response).unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();

        match parsed {
            Response::CacheCleared { count } => {
                assert_eq!(count, 5);
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn response_pong_serde_roundtrip() {
        let response = Response::Pong;
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, r#"{"type":"pong"}"#);

        let parsed: Response = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Response::Pong));
    }

    #[test]
    fn error_code_display() {
        assert_eq!(ErrorCode::Cancelled.to_string(), "cancelled");
        assert_eq!(ErrorCode::Timeout.to_string(), "timeout");
        assert_eq!(ErrorCode::InvalidRequest.to_string(), "invalid_request");
        assert_eq!(ErrorCode::InternalError.to_string(), "internal_error");
        assert_eq!(ErrorCode::ShuttingDown.to_string(), "shutting_down");
    }

    #[test]
    fn error_code_serde_roundtrip() {
        let codes = [
            ErrorCode::Cancelled,
            ErrorCode::Timeout,
            ErrorCode::InvalidRequest,
            ErrorCode::InternalError,
            ErrorCode::ShuttingDown,
        ];

        for code in codes {
            let json = serde_json::to_string(&code).unwrap();
            let parsed: ErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(code, parsed);
        }
    }

    #[test]
    fn invalid_json_returns_error() {
        let result: Result<Request, _> = serde_json::from_str("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn missing_type_field_returns_error() {
        let result: Result<Request, _> = serde_json::from_str(r#"{"prompt": "test"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_type_returns_error() {
        let result: Result<Request, _> = serde_json::from_str(r#"{"type": "unknown_type"}"#);
        assert!(result.is_err());
    }
}
