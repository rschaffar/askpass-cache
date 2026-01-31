//! Mock password prompt for testing.
//!
//! This module provides a configurable mock implementation of [`PasswordPrompt`]
//! that can be used in tests without requiring a display server.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use secrecy::SecretString;
use secure_askpass_core::{PasswordPrompt, PromptConfig, PromptError, PromptResponse};

/// A mock password prompt for testing.
///
/// This implementation allows configuring predetermined responses,
/// simulating errors, and tracking how many times it was called.
///
/// # Example
///
/// ```
/// use secure_askpass_daemon::prompt::MockPasswordPrompt;
/// use secure_askpass_core::{PromptConfig, PromptResponse, PasswordPrompt};
/// use secrecy::SecretString;
///
/// // Create a mock that returns a specific password
/// let mock = MockPasswordPrompt::with_password("test-password");
///
/// // Or create one that simulates cancellation
/// let mock_cancel = MockPasswordPrompt::cancelled();
/// ```
pub struct MockPasswordPrompt {
    /// The response to return (if any).
    response: Option<PromptResponse>,
    /// Error to return instead of response.
    error: Option<PromptError>,
    /// Number of times prompt was called.
    call_count: Arc<AtomicUsize>,
    /// Delay before responding (for timeout testing).
    delay: Option<std::time::Duration>,
}

impl MockPasswordPrompt {
    /// Create a mock that returns the given password.
    pub fn with_password(password: impl Into<String>) -> Self {
        Self {
            response: Some(PromptResponse {
                credential: SecretString::from(password.into()),
                should_cache: true,
            }),
            error: None,
            call_count: Arc::new(AtomicUsize::new(0)),
            delay: None,
        }
    }

    /// Create a mock that returns the given response.
    pub fn with_response(response: PromptResponse) -> Self {
        Self {
            response: Some(response),
            error: None,
            call_count: Arc::new(AtomicUsize::new(0)),
            delay: None,
        }
    }

    /// Create a mock that simulates user cancellation.
    pub fn cancelled() -> Self {
        Self {
            response: None,
            error: Some(PromptError::Cancelled),
            call_count: Arc::new(AtomicUsize::new(0)),
            delay: None,
        }
    }

    /// Create a mock that simulates timeout.
    pub fn timeout(seconds: u64) -> Self {
        Self {
            response: None,
            error: Some(PromptError::Timeout(seconds)),
            call_count: Arc::new(AtomicUsize::new(0)),
            delay: None,
        }
    }

    /// Create a mock that returns an error.
    pub fn with_error(error: PromptError) -> Self {
        Self {
            response: None,
            error: Some(error),
            call_count: Arc::new(AtomicUsize::new(0)),
            delay: None,
        }
    }

    /// Add a delay before responding (useful for timeout testing).
    pub fn with_delay(mut self, delay: std::time::Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    /// Set whether the mock should indicate caching.
    pub fn with_cache(mut self, should_cache: bool) -> Self {
        if let Some(ref mut response) = self.response {
            response.should_cache = should_cache;
        }
        self
    }

    /// Get the number of times prompt was called.
    pub fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }

    /// Get a clone of the call counter for external tracking.
    pub fn call_counter(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.call_count)
    }
}

impl Default for MockPasswordPrompt {
    fn default() -> Self {
        Self::with_password("mock-password")
    }
}

impl PasswordPrompt for MockPasswordPrompt {
    fn prompt(
        &self,
        _config: PromptConfig,
    ) -> Pin<Box<dyn Future<Output = Result<PromptResponse, PromptError>> + Send + '_>> {
        // Increment call count
        self.call_count.fetch_add(1, Ordering::SeqCst);

        let response = self.response.clone();
        let error = self.error.clone();
        let delay = self.delay;

        Box::pin(async move {
            // Apply delay if configured
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }

            // Return error if configured
            if let Some(err) = error {
                return Err(err);
            }

            // Return response if configured
            response.ok_or(PromptError::Cancelled)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[tokio::test]
    async fn mock_returns_password() {
        let mock = MockPasswordPrompt::with_password("test-pass");
        let config = PromptConfig::default();

        let response = mock.prompt(config).await.unwrap();
        assert_eq!(response.credential.expose_secret(), "test-pass");
        assert!(response.should_cache);
    }

    #[tokio::test]
    async fn mock_returns_cancelled() {
        let mock = MockPasswordPrompt::cancelled();
        let config = PromptConfig::default();

        let result = mock.prompt(config).await;
        assert!(matches!(result, Err(PromptError::Cancelled)));
    }

    #[tokio::test]
    async fn mock_returns_timeout() {
        let mock = MockPasswordPrompt::timeout(30);
        let config = PromptConfig::default();

        let result = mock.prompt(config).await;
        assert!(matches!(result, Err(PromptError::Timeout(30))));
    }

    #[tokio::test]
    async fn mock_tracks_call_count() {
        let mock = MockPasswordPrompt::default();
        let config = PromptConfig::default();

        assert_eq!(mock.call_count(), 0);

        let _ = mock.prompt(config.clone()).await;
        assert_eq!(mock.call_count(), 1);

        let _ = mock.prompt(config.clone()).await;
        assert_eq!(mock.call_count(), 2);
    }

    #[tokio::test]
    async fn mock_with_cache_false() {
        let mock = MockPasswordPrompt::with_password("test").with_cache(false);
        let config = PromptConfig::default();

        let response = mock.prompt(config).await.unwrap();
        assert!(!response.should_cache);
    }

    #[tokio::test]
    async fn mock_with_delay() {
        use std::time::{Duration, Instant};

        let mock = MockPasswordPrompt::with_password("test").with_delay(Duration::from_millis(50));
        let config = PromptConfig::default();

        let start = Instant::now();
        let _ = mock.prompt(config).await;
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_millis(50));
    }

    #[test]
    fn mock_default_returns_mock_password() {
        let mock = MockPasswordPrompt::default();
        assert!(mock.response.is_some());
    }
}
