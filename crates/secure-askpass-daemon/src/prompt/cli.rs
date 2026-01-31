//! CLI password prompt for testing and headless systems.
//!
//! This module provides a simple terminal-based password prompt using
//! `rpassword` for secure input (no echo).

use std::future::Future;
use std::io::{self, Write};
use std::pin::Pin;

use secrecy::SecretString;
use secure_askpass_core::{PasswordPrompt, PromptConfig, PromptError, PromptResponse};
use tracing::debug;

/// CLI-based password prompt.
///
/// This implementation uses the terminal for password entry, suitable for
/// testing or headless systems.
pub struct CliPasswordPrompt;

impl CliPasswordPrompt {
    /// Create a new CLI password prompt.
    pub fn new() -> Self {
        Self
    }
}

impl Default for CliPasswordPrompt {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordPrompt for CliPasswordPrompt {
    fn prompt(
        &self,
        config: PromptConfig,
    ) -> Pin<Box<dyn Future<Output = Result<PromptResponse, PromptError>> + Send + '_>> {
        Box::pin(async move {
            // We need to run this in a blocking context since it uses stdin
            let result = tokio::task::spawn_blocking(move || {
                // Print prompt
                print!("{} ", config.prompt_text);
                io::stdout().flush().map_err(|e| {
                    PromptError::UiError(format!("Failed to flush stdout: {}", e))
                })?;

                // Read password (no echo)
                let password = rpassword::read_password().map_err(|e| {
                    PromptError::UiError(format!("Failed to read password: {}", e))
                })?;

                if password.is_empty() {
                    return Err(PromptError::Cancelled);
                }

                debug!("Password entered via CLI");

                Ok(PromptResponse {
                    credential: SecretString::from(password),
                    should_cache: true, // Always cache for CLI (no checkbox)
                })
            })
            .await
            .map_err(|e| PromptError::UiError(format!("Task failed: {}", e)))?;

            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_cli_prompt() {
        let _prompt = CliPasswordPrompt::new();
    }
}
