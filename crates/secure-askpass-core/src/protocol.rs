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
    /// Request a credential from the cache.
    /// Returns `CacheMiss` if not cached (client should prompt user and use `StoreCredential`).
    GetCredential {
        /// The prompt text (used for cache ID auto-detection).
        prompt: String,

        /// The cache ID for this credential.
        /// Use "auto" to auto-detect from the prompt text.
        #[serde(default = "default_cache_id")]
        cache_id: String,

        /// The type of credential (optional, auto-detected if not provided).
        #[serde(default)]
        cache_type: Option<CacheType>,
    },

    /// Store a credential in the cache (after client prompts user).
    StoreCredential {
        /// The cache ID for this credential.
        cache_id: String,

        /// The credential value to store.
        #[serde(
            serialize_with = "serialize_secret",
            deserialize_with = "deserialize_secret"
        )]
        value: SecretString,

        /// The type of credential (for TTL defaults).
        #[serde(default)]
        cache_type: Option<CacheType>,

        /// TTL override in seconds (optional, uses cache type default if not provided).
        #[serde(default)]
        ttl: Option<u64>,
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

/// A response from the daemon to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// A credential response (cache hit).
    Credential {
        /// The credential value.
        /// Note: This is serialized as a plain string in JSON for IPC.
        #[serde(
            serialize_with = "serialize_secret",
            deserialize_with = "deserialize_secret"
        )]
        value: SecretString,
    },

    /// Cache miss - credential not found.
    /// Client should prompt the user and use `StoreCredential` to cache the result.
    CacheMiss {
        /// The resolved cache ID (after auto-detection).
        cache_id: String,

        /// The detected cache type.
        cache_type: CacheType,
    },

    /// Confirmation that a credential was stored.
    Stored,

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
    /// Create a credential response (cache hit).
    pub fn credential(value: SecretString) -> Self {
        Response::Credential { value }
    }

    /// Create a cache miss response.
    pub fn cache_miss(cache_id: impl Into<String>, cache_type: CacheType) -> Self {
        Response::CacheMiss {
            cache_id: cache_id.into(),
            cache_type,
        }
    }

    /// Create a stored confirmation response.
    pub fn stored() -> Self {
        Response::Stored
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
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();

        match parsed {
            Request::GetCredential {
                prompt,
                cache_id,
                cache_type,
            } => {
                assert_eq!(prompt, "Enter PIN for key");
                assert_eq!(cache_id, "ssh-fido:SHA256:abc");
                assert_eq!(cache_type, Some(CacheType::Ssh));
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
            } => {
                assert_eq!(prompt, "Enter password");
                assert_eq!(cache_id, "auto");
                assert_eq!(cache_type, None);
            }
            _ => panic!("Wrong request type"),
        }
    }

    #[test]
    fn request_store_credential_serde_roundtrip() {
        let request = Request::StoreCredential {
            cache_id: "ssh-fido:SHA256:abc".to_string(),
            value: SecretString::from("secret123"),
            cache_type: Some(CacheType::Ssh),
            ttl: Some(1800),
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();

        match parsed {
            Request::StoreCredential {
                cache_id,
                value,
                cache_type,
                ttl,
            } => {
                assert_eq!(cache_id, "ssh-fido:SHA256:abc");
                assert_eq!(value.expose_secret(), "secret123");
                assert_eq!(cache_type, Some(CacheType::Ssh));
                assert_eq!(ttl, Some(1800));
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
        let response = Response::credential(SecretString::from("secret123"));

        let json = serde_json::to_string(&response).unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();

        match parsed {
            Response::Credential { value } => {
                assert_eq!(value.expose_secret(), "secret123");
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn response_cache_miss_serde_roundtrip() {
        let response = Response::cache_miss("ssh-fido:SHA256:abc", CacheType::Ssh);

        let json = serde_json::to_string(&response).unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();

        match parsed {
            Response::CacheMiss {
                cache_id,
                cache_type,
            } => {
                assert_eq!(cache_id, "ssh-fido:SHA256:abc");
                assert_eq!(cache_type, CacheType::Ssh);
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn response_stored_serde_roundtrip() {
        let response = Response::stored();

        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, r#"{"type":"stored"}"#);

        let parsed: Response = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Response::Stored));
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
        assert_eq!(ErrorCode::InvalidRequest.to_string(), "invalid_request");
        assert_eq!(ErrorCode::InternalError.to_string(), "internal_error");
        assert_eq!(ErrorCode::ShuttingDown.to_string(), "shutting_down");
    }

    #[test]
    fn error_code_serde_roundtrip() {
        let codes = [
            ErrorCode::Cancelled,
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
