//! Core types and utilities for secure-askpass.
//!
//! This crate provides the fundamental building blocks for the secure-askpass
//! credential caching system. It is intentionally UI-agnostic to allow:
//!
//! - Security audits to focus on core modules
//! - Unit tests without a display server
//! - Different UI backends (GTK4, libadwaita, CLI)
//!
//! # Modules
//!
//! - [`types`]: Core data types (`CacheType`, `PromptConfig`, `PromptResponse`)
//! - [`protocol`]: IPC protocol types (`Request`, `Response`, `ErrorCode`)
//! - [`traits`]: Pluggable component traits (`PasswordPrompt`, `SocketProvider`, `EventMonitor`)
//! - [`cache`]: Secure credential cache with memory locking and TTL expiry
//! - [`cache_id`]: Auto-detection of cache IDs from prompt text
//!
//! # Example
//!
//! ```
//! use secure_askpass_core::types::{CacheType, PromptConfig};
//! use secure_askpass_core::protocol::{Request, Response};
//!
//! // Create a credential request
//! let request = Request::GetCredential {
//!     prompt: "Enter PIN for key".to_string(),
//!     cache_id: "auto".to_string(),
//!     cache_type: Some(CacheType::Ssh),
//!     ttl: None,
//!     allow_cache: true,
//!     echo: false,
//! };
//!
//! // Serialize to JSON for IPC
//! let json = serde_json::to_string(&request).unwrap();
//! assert!(json.contains("get_credential"));
//! ```

pub mod cache;
pub mod cache_id;
pub mod protocol;
pub mod traits;
pub mod types;

// Re-export commonly used types at the crate root for convenience
pub use cache::{CachedCredential, CredentialCache};
pub use cache_id::{detect_cache_id, Confidence, DetectionResult};
pub use protocol::{ErrorCode, ProtocolError, Request, Response};
pub use traits::{
    EventError, EventMonitor, NoOpEventMonitor, PasswordPrompt, PromptError, SocketError,
    SocketProvider, SystemEvent,
};
pub use types::{CacheType, PromptConfig, PromptResponse};
