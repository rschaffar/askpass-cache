//! Askpass cache daemon implementation.
//!
//! This crate provides the main daemon process for askpass-cache,
//! including socket handling and cache management.
//!
//! Note: The daemon only manages the credential cache. Password prompting
//! is handled by the client (askpass-client), which inherits the display
//! environment from the calling process.

pub mod daemon;
pub mod socket;

// Re-export main components
pub use daemon::Daemon;
pub use socket::{default_provider, ManualSocketProvider, SystemdSocketProvider};
