//! Core types and utilities for askpass-cache.
//!
//! This crate provides the fundamental building blocks for the askpass-cache
//! credential caching system. It is intentionally UI-agnostic - the daemon
//! only handles caching, while the client handles user prompts.
//!
//! # Modules
//!
//! - [`types`]: Core data types (`CacheType`)
//! - [`protocol`]: IPC protocol types (`Request`, `Response`, `ErrorCode`)
//! - [`traits`]: Pluggable component traits (`SocketProvider`, `EventMonitor`)
//! - [`cache`]: Secure credential cache with memory locking and TTL expiry
//! - [`cache_id`]: Auto-detection of cache IDs from prompt text
//!
//! # Example
//!
//! ```
//! use askpass_cache_core::types::CacheType;
//! use askpass_cache_core::protocol::{Request, Response};
//!
//! // Create a credential request
//! let request = Request::GetCredential {
//!     prompt: "Enter PIN for key".to_string(),
//!     cache_id: "auto".to_string(),
//!     cache_type: Some(CacheType::Ssh),
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
pub use protocol::{short_id, CacheEntryInfo, ErrorCode, ProtocolError, Request, Response};
pub use traits::{
    EventError, EventMonitor, NoOpEventMonitor, SocketError, SocketProvider, SystemEvent,
};
pub use types::CacheType;
