//! Protocol types for client-daemon communication.
//!
//! The askpass-cache protocol uses JSON over Unix sockets with newline-delimited messages.
//! This module defines the request and response types for the protocol.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::CacheType;

/// Generate an 8-character short ID from a cache ID.
///
/// This creates a human-friendly identifier for use in CLI tools.
/// The ID is deterministic - the same cache_id always produces the same short ID.
///
/// # Example
///
/// ```
/// use askpass_cache_core::protocol::short_id;
///
/// let id = short_id("ssh-fido:SHA256:xK3NvbHvA5N6TjXd");
/// assert_eq!(id.len(), 8);
/// assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
/// ```
pub fn short_id(cache_id: &str) -> String {
    let mut hasher = DefaultHasher::new();
    cache_id.hash(&mut hasher);
    format!("{:08x}", hasher.finish() as u32)
}

/// Metadata about a cached credential (no secrets exposed).
///
/// Used by the `ListCache` command to show what's in the cache
/// without revealing credential values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntryInfo {
    /// Short 8-character hex ID for easy reference in CLI.
    pub id: String,

    /// Full cache key (e.g., "ssh-fido:SHA256:..." or "git:https://github.com").
    pub cache_id: String,

    /// Type of credential.
    pub cache_type: CacheType,

    /// Seconds until this entry expires (None if already expired but not cleaned up).
    pub ttl_remaining_secs: Option<u64>,
}

impl CacheEntryInfo {
    /// Create a new cache entry info.
    pub fn new(
        cache_id: impl Into<String>,
        cache_type: CacheType,
        ttl_remaining_secs: Option<u64>,
    ) -> Self {
        let cache_id = cache_id.into();
        Self {
            id: short_id(&cache_id),
            cache_id,
            cache_type,
            ttl_remaining_secs,
        }
    }
}

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

        /// Whether the credential is confirmed (default: true for backwards compatibility).
        /// Unconfirmed credentials are not returned by `GetCredential` until confirmed.
        #[serde(default = "default_confirmed")]
        confirmed: Option<bool>,
    },

    /// Confirm a previously stored unconfirmed credential.
    /// This promotes the credential so it can be returned by `GetCredential`.
    ConfirmCredential {
        /// The cache ID of the credential to confirm.
        cache_id: String,
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

    /// List all cached credentials (metadata only, no secrets).
    ListCache,
}

fn default_cache_id() -> String {
    "auto".to_string()
}

fn default_confirmed() -> Option<bool> {
    Some(true) // Default to confirmed for backwards compatibility
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

    /// Confirmation that a credential was confirmed (promoted from unconfirmed state).
    Confirmed,

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

    /// List of cached credentials (metadata only).
    CacheEntries {
        /// Information about each cached credential.
        entries: Vec<CacheEntryInfo>,
    },
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

    /// Requested resource not found.
    NotFound,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCode::Cancelled => write!(f, "cancelled"),
            ErrorCode::InvalidRequest => write!(f, "invalid_request"),
            ErrorCode::InternalError => write!(f, "internal_error"),
            ErrorCode::ShuttingDown => write!(f, "shutting_down"),
            ErrorCode::NotFound => write!(f, "not_found"),
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

    /// Create a confirmed response (credential promoted from unconfirmed).
    pub fn confirmed() -> Self {
        Response::Confirmed
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

    /// Create a cache entries response.
    pub fn cache_entries(entries: Vec<CacheEntryInfo>) -> Self {
        Response::CacheEntries { entries }
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
            confirmed: Some(true),
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();

        match parsed {
            Request::StoreCredential {
                cache_id,
                value,
                cache_type,
                ttl,
                confirmed,
            } => {
                assert_eq!(cache_id, "ssh-fido:SHA256:abc");
                assert_eq!(value.expose_secret(), "secret123");
                assert_eq!(cache_type, Some(CacheType::Ssh));
                assert_eq!(ttl, Some(1800));
                assert_eq!(confirmed, Some(true));
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
        assert_eq!(ErrorCode::NotFound.to_string(), "not_found");
    }

    #[test]
    fn error_code_serde_roundtrip() {
        let codes = [
            ErrorCode::Cancelled,
            ErrorCode::InvalidRequest,
            ErrorCode::InternalError,
            ErrorCode::ShuttingDown,
            ErrorCode::NotFound,
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

    #[test]
    fn short_id_is_8_hex_chars() {
        let id = super::short_id("ssh-fido:SHA256:xK3NvbHvA5N6TjXd");
        assert_eq!(id.len(), 8);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn short_id_is_deterministic() {
        let id1 = super::short_id("test-cache-id");
        let id2 = super::short_id("test-cache-id");
        assert_eq!(id1, id2);
    }

    #[test]
    fn short_id_different_inputs_different_outputs() {
        let id1 = super::short_id("cache-id-1");
        let id2 = super::short_id("cache-id-2");
        assert_ne!(id1, id2);
    }

    #[test]
    fn cache_entry_info_new() {
        let info = CacheEntryInfo::new("ssh-fido:SHA256:abc", CacheType::Ssh, Some(1800));
        assert_eq!(info.id.len(), 8);
        assert_eq!(info.cache_id, "ssh-fido:SHA256:abc");
        assert_eq!(info.cache_type, CacheType::Ssh);
        assert_eq!(info.ttl_remaining_secs, Some(1800));
    }

    #[test]
    fn cache_entry_info_serde_roundtrip() {
        let info = CacheEntryInfo::new("git:https://github.com", CacheType::Git, Some(7200));
        let json = serde_json::to_string(&info).unwrap();
        let parsed: CacheEntryInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, parsed);
    }

    #[test]
    fn request_list_cache_serde_roundtrip() {
        let request = Request::ListCache;
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(json, r#"{"type":"list_cache"}"#);

        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Request::ListCache));
    }

    #[test]
    fn response_cache_entries_serde_roundtrip() {
        let entries = vec![
            CacheEntryInfo::new("ssh-fido:SHA256:abc", CacheType::Ssh, Some(1800)),
            CacheEntryInfo::new("git:https://github.com", CacheType::Git, Some(7200)),
        ];
        let response = Response::cache_entries(entries.clone());

        let json = serde_json::to_string(&response).unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();

        match parsed {
            Response::CacheEntries {
                entries: parsed_entries,
            } => {
                assert_eq!(parsed_entries.len(), 2);
                assert_eq!(parsed_entries[0].cache_type, CacheType::Ssh);
                assert_eq!(parsed_entries[1].cache_type, CacheType::Git);
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn response_cache_entries_empty() {
        let response = Response::cache_entries(vec![]);
        let json = serde_json::to_string(&response).unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();

        match parsed {
            Response::CacheEntries { entries } => {
                assert!(entries.is_empty());
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn request_store_credential_with_confirmed_false() {
        let request = Request::StoreCredential {
            cache_id: "test-key".to_string(),
            value: SecretString::from("secret"),
            cache_type: Some(CacheType::Ssh),
            ttl: None,
            confirmed: Some(false),
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();

        match parsed {
            Request::StoreCredential { confirmed, .. } => {
                assert_eq!(confirmed, Some(false));
            }
            _ => panic!("Wrong request type"),
        }
    }

    #[test]
    fn request_store_credential_confirmed_defaults_to_true() {
        // Test that missing confirmed field defaults to true (backwards compat)
        let json = r#"{"type":"store_credential","cache_id":"test","value":"secret"}"#;
        let parsed: Request = serde_json::from_str(json).unwrap();

        match parsed {
            Request::StoreCredential { confirmed, .. } => {
                assert_eq!(confirmed, Some(true));
            }
            _ => panic!("Wrong request type"),
        }
    }

    #[test]
    fn request_confirm_credential_serde_roundtrip() {
        let request = Request::ConfirmCredential {
            cache_id: "ssh-fido:SHA256:abc".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("confirm_credential"));

        let parsed: Request = serde_json::from_str(&json).unwrap();

        match parsed {
            Request::ConfirmCredential { cache_id } => {
                assert_eq!(cache_id, "ssh-fido:SHA256:abc");
            }
            _ => panic!("Wrong request type"),
        }
    }

    #[test]
    fn response_confirmed_serde_roundtrip() {
        let response = Response::confirmed();
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, r#"{"type":"confirmed"}"#);

        let parsed: Response = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Response::Confirmed));
    }

    #[test]
    fn error_code_not_found() {
        let response = Response::error(ErrorCode::NotFound, "Credential not found");
        let json = serde_json::to_string(&response).unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();

        match parsed {
            Response::Error { code, message } => {
                assert_eq!(code, ErrorCode::NotFound);
                assert_eq!(message, "Credential not found");
            }
            _ => panic!("Wrong response type"),
        }
    }
}
