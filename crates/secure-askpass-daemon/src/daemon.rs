//! Main daemon orchestration.
//!
//! This module provides the core `Daemon` struct that coordinates:
//! - Socket listening for client connections
//! - Credential cache management
//! - Password prompt display
//! - Request/response handling

use std::sync::Arc;
use std::time::Duration;

use secure_askpass_core::{
    cache_id::detect_cache_id, CacheType, CredentialCache, ErrorCode, EventMonitor,
    NoOpEventMonitor, PasswordPrompt, PromptConfig, PromptError, Request, Response, SocketProvider,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// The main daemon struct.
///
/// This struct coordinates all the daemon's components and handles
/// the main event loop.
pub struct Daemon<P: PasswordPrompt, S: SocketProvider, E: EventMonitor> {
    /// The credential cache.
    cache: Arc<Mutex<CredentialCache>>,
    /// The password prompt implementation.
    prompt: P,
    /// The socket provider.
    socket_provider: S,
    /// The event monitor (used in Phase 3 for D-Bus event monitoring).
    #[allow(dead_code)]
    event_monitor: Mutex<E>,
}

impl<P: PasswordPrompt, S: SocketProvider> Daemon<P, S, NoOpEventMonitor> {
    /// Create a new daemon without event monitoring.
    pub fn new(prompt: P, socket_provider: S) -> Self {
        Self {
            cache: Arc::new(Mutex::new(CredentialCache::new())),
            prompt,
            socket_provider,
            event_monitor: Mutex::new(NoOpEventMonitor),
        }
    }
}

impl<P: PasswordPrompt, S: SocketProvider, E: EventMonitor> Daemon<P, S, E> {
    /// Create a new daemon with event monitoring.
    pub fn with_event_monitor(prompt: P, socket_provider: S, event_monitor: E) -> Self {
        Self {
            cache: Arc::new(Mutex::new(CredentialCache::new())),
            prompt,
            socket_provider,
            event_monitor: Mutex::new(event_monitor),
        }
    }

    /// Run the daemon main loop.
    ///
    /// This method listens for connections on the socket and handles
    /// incoming requests. It also monitors system events and clears
    /// the cache when appropriate.
    pub async fn run(&self) -> anyhow::Result<()> {
        let listener = self.socket_provider.listen().await?;
        info!(
            path = ?self.socket_provider.socket_path(),
            "Daemon listening for connections"
        );

        // Spawn cache cleanup task
        let cache_cleanup = Arc::clone(&self.cache);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let mut cache = cache_cleanup.lock().await;
                let removed = cache.cleanup_expired();
                if removed > 0 {
                    debug!(removed = removed, "Cleaned up expired credentials");
                }
            }
        });

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    debug!("Accepted connection");
                    let cache = Arc::clone(&self.cache);
                    // We can't easily share &self.prompt across tasks, so we handle inline
                    // In a real implementation, we'd use an Arc<dyn PasswordPrompt>
                    self.handle_connection(stream, cache).await;
                }
                Err(e) => {
                    error!(error = %e, "Failed to accept connection");
                }
            }
        }
    }

    /// Handle a single client connection.
    async fn handle_connection(&self, stream: UnixStream, cache: Arc<Mutex<CredentialCache>>) {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        // Read request
        match reader.read_line(&mut line).await {
            Ok(0) => {
                debug!("Client disconnected without sending request");
                return;
            }
            Ok(_) => {}
            Err(e) => {
                error!(error = %e, "Failed to read request");
                return;
            }
        }

        // Parse request
        let request = match Request::parse(line.trim()) {
            Ok(req) => req,
            Err(e) => {
                warn!(error = %e, "Failed to parse request");
                let response = Response::error(ErrorCode::InvalidRequest, e.to_string());
                let _ = self.send_response(&mut writer, &response).await;
                return;
            }
        };

        // Handle request
        let response = self.handle_request(request, cache).await;

        // Send response
        if let Err(e) = self.send_response(&mut writer, &response).await {
            error!(error = %e, "Failed to send response");
        }
    }

    /// Handle a parsed request.
    async fn handle_request(
        &self,
        request: Request,
        cache: Arc<Mutex<CredentialCache>>,
    ) -> Response {
        match request {
            Request::GetCredential {
                prompt,
                cache_id,
                cache_type,
                ttl,
                allow_cache,
                echo: _,
            } => {
                self.handle_get_credential(prompt, cache_id, cache_type, ttl, allow_cache, cache)
                    .await
            }
            Request::ClearCache {
                cache_id,
                cache_type,
            } => self.handle_clear_cache(cache_id, cache_type, cache).await,
            Request::Ping => Response::Pong,
        }
    }

    /// Handle a GetCredential request.
    async fn handle_get_credential(
        &self,
        prompt_text: String,
        cache_id: String,
        cache_type: Option<CacheType>,
        ttl: Option<u64>,
        allow_cache: bool,
        cache: Arc<Mutex<CredentialCache>>,
    ) -> Response {
        // Determine cache ID
        let (effective_cache_id, detected_type) = if cache_id == "auto" {
            let detection = detect_cache_id(&prompt_text);
            (detection.cache_id, detection.cache_type)
        } else {
            let detected_type = CacheType::from_cache_id(&cache_id);
            (cache_id, detected_type)
        };

        // Use provided cache type or detected type
        let effective_type = cache_type.unwrap_or(detected_type);

        debug!(
            cache_id = %effective_cache_id,
            cache_type = %effective_type,
            allow_cache = allow_cache,
            "Processing credential request"
        );

        // Check cache if allowed
        if allow_cache {
            let cache_guard = cache.lock().await;
            if let Some(cached) = cache_guard.get(&effective_cache_id) {
                debug!(cache_id = %effective_cache_id, "Returning cached credential");
                return Response::credential(cached.secret().clone(), true);
            }
            drop(cache_guard);
        }

        // Show prompt
        let config = PromptConfig {
            prompt_text,
            cache_id: effective_cache_id.clone(),
            cache_type: effective_type,
            timeout: Duration::from_secs(30),
            show_remember_checkbox: allow_cache,
            echo: false,
        };

        let prompt_result = self.prompt.prompt(config).await;

        match prompt_result {
            Ok(response) => {
                // Cache if requested
                if allow_cache && response.should_cache {
                    let ttl = ttl
                        .map(Duration::from_secs)
                        .unwrap_or_else(|| effective_type.default_ttl());

                    let mut cache_guard = cache.lock().await;
                    cache_guard.insert(
                        &effective_cache_id,
                        response.credential.clone(),
                        ttl,
                        effective_type,
                    );
                    debug!(
                        cache_id = %effective_cache_id,
                        ttl_secs = ttl.as_secs(),
                        "Cached credential"
                    );
                }

                Response::credential(response.credential, false)
            }
            Err(PromptError::Cancelled) => {
                Response::error(ErrorCode::Cancelled, "User cancelled the prompt")
            }
            Err(PromptError::Timeout(secs)) => Response::error(
                ErrorCode::Timeout,
                format!("Prompt timed out after {}s", secs),
            ),
            Err(e) => Response::error(ErrorCode::InternalError, e.to_string()),
        }
    }

    /// Handle a ClearCache request.
    async fn handle_clear_cache(
        &self,
        cache_id: String,
        cache_type: Option<CacheType>,
        cache: Arc<Mutex<CredentialCache>>,
    ) -> Response {
        let mut cache_guard = cache.lock().await;

        let count = if cache_id == "all" {
            if let Some(ct) = cache_type {
                cache_guard.clear_by_type(ct)
            } else {
                let count = cache_guard.len();
                cache_guard.clear_all();
                count
            }
        } else if cache_guard.remove(&cache_id) {
            1
        } else {
            0
        };

        info!(count = count, cache_id = %cache_id, "Cleared cache");
        Response::cache_cleared(count)
    }

    /// Send a response to the client.
    async fn send_response(
        &self,
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        response: &Response,
    ) -> anyhow::Result<()> {
        let json = response.to_json_line()?;
        writer.write_all(json.as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Get a reference to the cache (for testing).
    #[cfg(test)]
    pub fn cache(&self) -> &Arc<Mutex<CredentialCache>> {
        &self.cache
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::MockPasswordPrompt;
    use crate::socket::ManualSocketProvider;
    use secrecy::{ExposeSecret, SecretString};
    use tempfile::tempdir;

    #[tokio::test]
    async fn daemon_creation() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let prompt = MockPasswordPrompt::with_password("test");
        let socket = ManualSocketProvider::new(&socket_path);
        let _daemon = Daemon::new(prompt, socket);
    }

    #[tokio::test]
    async fn handle_ping_request() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let prompt = MockPasswordPrompt::with_password("test");
        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(prompt, socket);

        let cache = Arc::clone(daemon.cache());
        let response = daemon.handle_request(Request::Ping, cache).await;

        assert!(matches!(response, Response::Pong));
    }

    #[tokio::test]
    async fn handle_get_credential_from_cache() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let prompt = MockPasswordPrompt::with_password("prompted");
        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(prompt, socket);

        // Pre-populate cache
        {
            let mut cache = daemon.cache().lock().await;
            cache.insert(
                "test-key",
                SecretString::from("cached-password"),
                Duration::from_secs(3600),
                CacheType::Custom,
            );
        }

        let cache = Arc::clone(daemon.cache());
        let request = Request::GetCredential {
            prompt: "Enter password".to_string(),
            cache_id: "test-key".to_string(),
            cache_type: None,
            ttl: None,
            allow_cache: true,
            echo: false,
        };

        let response = daemon.handle_request(request, cache).await;

        match response {
            Response::Credential { value, from_cache } => {
                assert_eq!(value.expose_secret(), "cached-password");
                assert!(from_cache);
            }
            _ => panic!("Expected credential response"),
        }
    }

    #[tokio::test]
    async fn handle_get_credential_prompts_on_miss() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let prompt = MockPasswordPrompt::with_password("from-prompt");
        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(prompt, socket);

        let cache = Arc::clone(daemon.cache());
        let request = Request::GetCredential {
            prompt: "Enter password".to_string(),
            cache_id: "new-key".to_string(),
            cache_type: None,
            ttl: None,
            allow_cache: true,
            echo: false,
        };

        let response = daemon.handle_request(request, cache).await;

        match response {
            Response::Credential { value, from_cache } => {
                assert_eq!(value.expose_secret(), "from-prompt");
                assert!(!from_cache);
            }
            _ => panic!("Expected credential response"),
        }
    }

    #[tokio::test]
    async fn handle_cancelled_prompt() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let prompt = MockPasswordPrompt::cancelled();
        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(prompt, socket);

        let cache = Arc::clone(daemon.cache());
        let request = Request::GetCredential {
            prompt: "Enter password".to_string(),
            cache_id: "key".to_string(),
            cache_type: None,
            ttl: None,
            allow_cache: true,
            echo: false,
        };

        let response = daemon.handle_request(request, cache).await;

        match response {
            Response::Error { code, .. } => {
                assert_eq!(code, ErrorCode::Cancelled);
            }
            _ => panic!("Expected error response"),
        }
    }

    #[tokio::test]
    async fn handle_clear_cache_all() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let prompt = MockPasswordPrompt::with_password("test");
        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(prompt, socket);

        // Add some entries
        {
            let mut cache = daemon.cache().lock().await;
            cache.insert(
                "key1",
                SecretString::from("pass1"),
                Duration::from_secs(3600),
                CacheType::Ssh,
            );
            cache.insert(
                "key2",
                SecretString::from("pass2"),
                Duration::from_secs(3600),
                CacheType::Git,
            );
        }

        let cache = Arc::clone(daemon.cache());
        let request = Request::ClearCache {
            cache_id: "all".to_string(),
            cache_type: None,
        };

        let response = daemon.handle_request(request, cache).await;

        match response {
            Response::CacheCleared { count } => {
                assert_eq!(count, 2);
            }
            _ => panic!("Expected cache cleared response"),
        }

        // Verify cache is empty
        let cache = daemon.cache().lock().await;
        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn handle_clear_cache_by_type() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let prompt = MockPasswordPrompt::with_password("test");
        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(prompt, socket);

        // Add entries of different types
        {
            let mut cache = daemon.cache().lock().await;
            cache.insert(
                "ssh1",
                SecretString::from("pass1"),
                Duration::from_secs(3600),
                CacheType::Ssh,
            );
            cache.insert(
                "ssh2",
                SecretString::from("pass2"),
                Duration::from_secs(3600),
                CacheType::Ssh,
            );
            cache.insert(
                "git1",
                SecretString::from("pass3"),
                Duration::from_secs(3600),
                CacheType::Git,
            );
        }

        let cache = Arc::clone(daemon.cache());
        let request = Request::ClearCache {
            cache_id: "all".to_string(),
            cache_type: Some(CacheType::Ssh),
        };

        let response = daemon.handle_request(request, cache).await;

        match response {
            Response::CacheCleared { count } => {
                assert_eq!(count, 2);
            }
            _ => panic!("Expected cache cleared response"),
        }

        // Verify only SSH entries were cleared
        let cache = daemon.cache().lock().await;
        assert_eq!(cache.len(), 1);
        assert!(cache.get("git1").is_some());
    }

    #[tokio::test]
    async fn credential_is_cached_when_should_cache_true() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let prompt = MockPasswordPrompt::with_password("new-pass").with_cache(true);
        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(prompt, socket);

        let cache = Arc::clone(daemon.cache());
        let request = Request::GetCredential {
            prompt: "Enter password".to_string(),
            cache_id: "cache-me".to_string(),
            cache_type: None,
            ttl: None,
            allow_cache: true,
            echo: false,
        };

        let _ = daemon.handle_request(request, cache).await;

        // Verify credential was cached
        let cache = daemon.cache().lock().await;
        let cached = cache.get("cache-me").expect("should be cached");
        assert_eq!(cached.secret().expose_secret(), "new-pass");
    }

    #[tokio::test]
    async fn credential_not_cached_when_should_cache_false() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let prompt = MockPasswordPrompt::with_password("no-cache").with_cache(false);
        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(prompt, socket);

        let cache = Arc::clone(daemon.cache());
        let request = Request::GetCredential {
            prompt: "Enter password".to_string(),
            cache_id: "dont-cache-me".to_string(),
            cache_type: None,
            ttl: None,
            allow_cache: true,
            echo: false,
        };

        let _ = daemon.handle_request(request, cache).await;

        // Verify credential was NOT cached
        let cache = daemon.cache().lock().await;
        assert!(cache.get("dont-cache-me").is_none());
    }
}
