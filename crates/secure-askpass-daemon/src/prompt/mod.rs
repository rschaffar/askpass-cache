//! Password prompt implementations.
//!
//! This module provides implementations of the [`PasswordPrompt`] trait:
//!
//! - [`Gtk4PasswordPrompt`]: GTK4-based GUI dialog (production)
//! - [`MockPasswordPrompt`]: Configurable mock for testing
//!
//! Both implement the [`PasswordPrompt`] trait from `secure-askpass-core`.

mod gtk4_prompt;
mod mock;

pub use gtk4_prompt::Gtk4PasswordPrompt;
pub use mock::MockPasswordPrompt;
