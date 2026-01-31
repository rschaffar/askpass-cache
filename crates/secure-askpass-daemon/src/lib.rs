//! Secure askpass daemon implementation.
//!
//! This crate provides the main daemon process for secure-askpass,
//! including socket handling, password prompting, and cache management.

pub mod daemon;
pub mod prompt;
pub mod socket;

// Re-export main components
pub use daemon::Daemon;
pub use prompt::{CliPasswordPrompt, Gtk4PasswordPrompt, MockPasswordPrompt};
pub use socket::{default_provider, ManualSocketProvider, SystemdSocketProvider};
