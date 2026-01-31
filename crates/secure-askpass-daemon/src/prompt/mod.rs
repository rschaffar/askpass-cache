//! Password prompt implementations.
//!
//! This module provides implementations of the [`PasswordPrompt`] trait:
//!
//! - [`Gtk4PasswordPrompt`]: GTK4-based GUI dialog (production)
//! - [`CliPasswordPrompt`]: Terminal-based prompt for testing/headless
//! - [`MockPasswordPrompt`]: Configurable mock for testing
//!
//! All implement the [`PasswordPrompt`] trait from `secure-askpass-core`.

mod cli;
mod gtk4_prompt;
mod mock;

pub use cli::CliPasswordPrompt;
pub use gtk4_prompt::Gtk4PasswordPrompt;
pub use mock::MockPasswordPrompt;
