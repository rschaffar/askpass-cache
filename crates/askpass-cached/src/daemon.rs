//! Main daemon orchestration.
//!
//! This module provides the core `Daemon` struct that coordinates:
//! - Socket listening for client connections
//! - Credential cache management
//! - Request/response handling
//!
//! Note: The daemon does NOT handle prompting - that's the client's job.
//! The daemon only manages the credential cache.

use std::sync::Arc;
use std::time::Duration;

use askpass_cache_core::{
    cache_id::detect_cache_id, CacheEntryInfo, CacheType, CredentialCache, ErrorCode, EventMonitor,
    NoOpEventMonitor, Request, Response, SocketProvider,
};
use secrecy::SecretString;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// The main daemon struct.
///
/// This struct coordinates all the daemon's components and handles
/// the main event loop. The daemon only manages caching - it does not
/// display any UI prompts.
pub struct Daemon<S: SocketProvider, E: EventMonitor> {
    /// The credential cache.
    cache: Arc<Mutex<CredentialCache>>,
    /// The socket provider.
    socket_provider: S,
    /// The event monitor (used in Phase 3 for D-Bus event monitoring).
    #[allow(dead_code)]
    event_monitor: Mutex<E>,
}

impl<S: SocketProvider> Daemon<S, NoOpEventMonitor> {
    /// Create a new daemon without event monitoring.
    pub fn new(socket_provider: S) -> Self {
        Self {
            cache: Arc::new(Mutex::new(CredentialCache::new())),
            socket_provider,
            event_monitor: Mutex::new(NoOpEventMonitor),
        }
    }
}

impl<S: SocketProvider, E: EventMonitor> Daemon<S, E> {
    /// Create a new daemon with event monitoring.
    pub fn with_event_monitor(socket_provider: S, event_monitor: E) -> Self {
        Self {
            cache: Arc::new(Mutex::new(CredentialCache::new())),
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
            } => {
                self.handle_get_credential(prompt, cache_id, cache_type, cache)
                    .await
            }
            Request::StoreCredential {
                cache_id,
                value,
                cache_type,
                ttl,
                confirmed,
            } => {
                self.handle_store_credential(cache_id, value, cache_type, ttl, confirmed, cache)
                    .await
            }
            Request::ClearCache {
                cache_id,
                cache_type,
            } => self.handle_clear_cache(cache_id, cache_type, cache).await,
            Request::ConfirmCredential { cache_id } => {
                self.handle_confirm_credential(cache_id, cache).await
            }
            Request::Ping => Response::Pong,
            Request::ListCache => self.handle_list_cache(cache).await,
        }
    }

    /// Handle a GetCredential request.
    ///
    /// Returns:
    /// - `Credential` if a confirmed credential is cached
    /// - `UnconfirmedCredential` if an unconfirmed credential exists (user should confirm)
    /// - `CacheMiss` if nothing is cached
    ///
    /// The client is responsible for:
    /// - On `Credential`: printing the value to stdout
    /// - On `UnconfirmedCredential`: showing a confirmation dialog
    /// - On `CacheMiss`: prompting the user and calling StoreCredential
    async fn handle_get_credential(
        &self,
        prompt_text: String,
        cache_id: String,
        cache_type: Option<CacheType>,
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
            "Processing credential request"
        );

        let cache_guard = cache.lock().await;

        // Check for CONFIRMED credential first
        if let Some(cached) = cache_guard.get(&effective_cache_id) {
            debug!(cache_id = %effective_cache_id, "Returning confirmed credential");
            return Response::credential(cached.secret().clone());
        }

        // Check for UNCONFIRMED credential
        if let Some(cached) = cache_guard.get_any(&effective_cache_id) {
            if !cached.is_confirmed() {
                debug!(cache_id = %effective_cache_id, "Returning unconfirmed credential for confirmation");
                return Response::unconfirmed_credential(
                    effective_cache_id,
                    cached.cache_type(), // Use the stored cache type
                    cached.secret().clone(),
                );
            }
        }

        drop(cache_guard);

        // Cache miss - client should prompt user and call StoreCredential
        debug!(cache_id = %effective_cache_id, "Cache miss");
        Response::cache_miss(effective_cache_id, effective_type)
    }

    /// Handle a StoreCredential request.
    ///
    /// Stores a credential in the cache after the client has prompted the user.
    ///
    /// If `confirmed` is `false` (or `None` defaulting to `true`), the credential
    /// will be stored in an unconfirmed state and won't be returned by `GetCredential`
    /// until it is confirmed via `ConfirmCredential`.
    async fn handle_store_credential(
        &self,
        cache_id: String,
        value: SecretString,
        cache_type: Option<CacheType>,
        ttl: Option<u64>,
        confirmed: Option<bool>,
        cache: Arc<Mutex<CredentialCache>>,
    ) -> Response {
        let effective_type = cache_type.unwrap_or_else(|| CacheType::from_cache_id(&cache_id));
        let effective_ttl = ttl
            .map(Duration::from_secs)
            .unwrap_or_else(|| effective_type.default_ttl());
        let is_confirmed = confirmed.unwrap_or(true);

        let mut cache_guard = cache.lock().await;
        cache_guard.insert(
            &cache_id,
            value,
            effective_ttl,
            effective_type,
            is_confirmed,
        );

        debug!(
            cache_id = %cache_id,
            ttl_secs = effective_ttl.as_secs(),
            confirmed = is_confirmed,
            "Stored credential"
        );

        Response::stored()
    }

    /// Handle a ConfirmCredential request.
    ///
    /// Promotes an unconfirmed credential to confirmed state, making it
    /// available via `GetCredential`.
    async fn handle_confirm_credential(
        &self,
        cache_id: String,
        cache: Arc<Mutex<CredentialCache>>,
    ) -> Response {
        let mut cache_guard = cache.lock().await;

        if cache_guard.confirm(&cache_id) {
            info!(cache_id = %cache_id, "Credential confirmed");
            Response::confirmed()
        } else {
            debug!(cache_id = %cache_id, "Credential not found for confirmation");
            Response::error(
                ErrorCode::NotFound,
                format!("No unconfirmed credential found for cache_id: {}", cache_id),
            )
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

    /// Handle a ListCache request.
    ///
    /// Returns metadata about all cached credentials without exposing secrets.
    async fn handle_list_cache(&self, cache: Arc<Mutex<CredentialCache>>) -> Response {
        let cache_guard = cache.lock().await;
        let entries: Vec<CacheEntryInfo> = cache_guard
            .iter()
            .map(|(key, cred)| {
                CacheEntryInfo::new(
                    key.clone(),
                    cred.cache_type(),
                    cred.time_remaining().map(|d| d.as_secs()),
                )
            })
            .collect();

        debug!(count = entries.len(), "Listed cache entries");
        Response::cache_entries(entries)
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
    use crate::socket::ManualSocketProvider;
    use secrecy::ExposeSecret;
    use tempfile::tempdir;

    #[tokio::test]
    async fn daemon_creation() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let socket = ManualSocketProvider::new(&socket_path);
        let _daemon = Daemon::new(socket);
    }

    #[tokio::test]
    async fn handle_ping_request() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(socket);

        let cache = Arc::clone(daemon.cache());
        let response = daemon.handle_request(Request::Ping, cache).await;

        assert!(matches!(response, Response::Pong));
    }

    #[tokio::test]
    async fn handle_get_credential_returns_cached() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(socket);

        // Pre-populate cache with confirmed credential
        {
            let mut cache = daemon.cache().lock().await;
            cache.insert(
                "test-key",
                SecretString::from("cached-password"),
                Duration::from_secs(3600),
                CacheType::Custom,
                true, // confirmed
            );
        }

        let cache = Arc::clone(daemon.cache());
        let request = Request::GetCredential {
            prompt: "Enter password".to_string(),
            cache_id: "test-key".to_string(),
            cache_type: None,
        };

        let response = daemon.handle_request(request, cache).await;

        match response {
            Response::Credential { value } => {
                assert_eq!(value.expose_secret(), "cached-password");
            }
            _ => panic!("Expected credential response"),
        }
    }

    #[tokio::test]
    async fn handle_get_credential_returns_cache_miss() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(socket);

        let cache = Arc::clone(daemon.cache());
        let request = Request::GetCredential {
            prompt: "Enter password".to_string(),
            cache_id: "nonexistent-key".to_string(),
            cache_type: None,
        };

        let response = daemon.handle_request(request, cache).await;

        match response {
            Response::CacheMiss {
                cache_id,
                cache_type,
            } => {
                assert_eq!(cache_id, "nonexistent-key");
                assert_eq!(cache_type, CacheType::Custom);
            }
            _ => panic!("Expected cache miss response"),
        }
    }

    #[tokio::test]
    async fn handle_store_credential() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(socket);

        let cache = Arc::clone(daemon.cache());
        let request = Request::StoreCredential {
            cache_id: "new-key".to_string(),
            value: SecretString::from("new-password"),
            cache_type: Some(CacheType::Ssh),
            ttl: Some(1800),
            confirmed: Some(true),
        };

        let response = daemon.handle_request(request, cache).await;
        assert!(matches!(response, Response::Stored));

        // Verify it was stored and is accessible (confirmed)
        let cache = daemon.cache().lock().await;
        let cached = cache.get("new-key").expect("should be cached");
        assert_eq!(cached.secret().expose_secret(), "new-password");
    }

    #[tokio::test]
    async fn handle_clear_cache_all() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(socket);

        // Add some entries
        {
            let mut cache = daemon.cache().lock().await;
            cache.insert(
                "key1",
                SecretString::from("pass1"),
                Duration::from_secs(3600),
                CacheType::Ssh,
                true,
            );
            cache.insert(
                "key2",
                SecretString::from("pass2"),
                Duration::from_secs(3600),
                CacheType::Git,
                true,
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

        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(socket);

        // Add entries of different types
        {
            let mut cache = daemon.cache().lock().await;
            cache.insert(
                "ssh1",
                SecretString::from("pass1"),
                Duration::from_secs(3600),
                CacheType::Ssh,
                true,
            );
            cache.insert(
                "ssh2",
                SecretString::from("pass2"),
                Duration::from_secs(3600),
                CacheType::Ssh,
                true,
            );
            cache.insert(
                "git1",
                SecretString::from("pass3"),
                Duration::from_secs(3600),
                CacheType::Git,
                true,
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
    async fn auto_detect_cache_id() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(socket);

        let cache = Arc::clone(daemon.cache());
        let request = Request::GetCredential {
            prompt: "Enter PIN for ECDSA-SK key /home/user/.ssh/id_ecdsa_sk:".to_string(),
            cache_id: "auto".to_string(),
            cache_type: None,
        };

        let response = daemon.handle_request(request, cache).await;

        match response {
            Response::CacheMiss {
                cache_id,
                cache_type,
            } => {
                // Should detect as SSH type
                assert_eq!(cache_type, CacheType::Ssh);
                assert!(cache_id.starts_with("ssh-fido:"));
            }
            _ => panic!("Expected cache miss response"),
        }
    }

    #[tokio::test]
    async fn handle_list_cache_empty() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(socket);

        let cache = Arc::clone(daemon.cache());
        let response = daemon.handle_request(Request::ListCache, cache).await;

        match response {
            Response::CacheEntries { entries } => {
                assert!(entries.is_empty());
            }
            _ => panic!("Expected cache entries response"),
        }
    }

    #[tokio::test]
    async fn handle_list_cache_with_entries() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(socket);

        // Pre-populate cache
        {
            let mut cache = daemon.cache().lock().await;
            cache.insert(
                "ssh-fido:SHA256:abc123",
                SecretString::from("pin1"),
                Duration::from_secs(1800),
                CacheType::Ssh,
                true,
            );
            cache.insert(
                "git:https://github.com",
                SecretString::from("token"),
                Duration::from_secs(7200),
                CacheType::Git,
                true,
            );
        }

        let cache = Arc::clone(daemon.cache());
        let response = daemon.handle_request(Request::ListCache, cache).await;

        match response {
            Response::CacheEntries { entries } => {
                assert_eq!(entries.len(), 2);

                // Find entries by cache_id
                let ssh_entry = entries
                    .iter()
                    .find(|e| e.cache_id == "ssh-fido:SHA256:abc123");
                let git_entry = entries
                    .iter()
                    .find(|e| e.cache_id == "git:https://github.com");

                assert!(ssh_entry.is_some());
                assert!(git_entry.is_some());

                let ssh = ssh_entry.unwrap();
                assert_eq!(ssh.cache_type, CacheType::Ssh);
                assert_eq!(ssh.id.len(), 8); // Short ID is 8 hex chars
                assert!(ssh.ttl_remaining_secs.is_some());

                let git = git_entry.unwrap();
                assert_eq!(git.cache_type, CacheType::Git);
            }
            _ => panic!("Expected cache entries response"),
        }
    }

    #[tokio::test]
    async fn handle_store_unconfirmed_credential() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(socket);

        // Store an unconfirmed credential
        let cache = Arc::clone(daemon.cache());
        let request = Request::StoreCredential {
            cache_id: "test-key".to_string(),
            value: SecretString::from("secret"),
            cache_type: Some(CacheType::Ssh),
            ttl: None,
            confirmed: Some(false), // Unconfirmed
        };

        let response = daemon.handle_request(request, cache).await;
        assert!(matches!(response, Response::Stored));

        // Verify it's returned as UnconfirmedCredential by GetCredential
        let cache = Arc::clone(daemon.cache());
        let request = Request::GetCredential {
            prompt: "test".to_string(),
            cache_id: "test-key".to_string(),
            cache_type: None,
        };

        let response = daemon.handle_request(request, cache).await;
        // Should return UnconfirmedCredential so user can confirm or re-enter
        match response {
            Response::UnconfirmedCredential {
                cache_id, value, ..
            } => {
                assert_eq!(cache_id, "test-key");
                assert_eq!(value.expose_secret(), "secret");
            }
            _ => panic!("Expected UnconfirmedCredential response"),
        }
    }

    #[tokio::test]
    async fn handle_confirm_credential_success() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(socket);

        // Store an unconfirmed credential directly in cache
        {
            let mut cache = daemon.cache().lock().await;
            cache.insert(
                "test-key",
                SecretString::from("secret"),
                Duration::from_secs(3600),
                CacheType::Ssh,
                false, // Unconfirmed
            );
        }

        // Confirm it
        let cache = Arc::clone(daemon.cache());
        let request = Request::ConfirmCredential {
            cache_id: "test-key".to_string(),
        };

        let response = daemon.handle_request(request, cache).await;
        assert!(matches!(response, Response::Confirmed));

        // Now it should be accessible via GetCredential
        let cache = Arc::clone(daemon.cache());
        let request = Request::GetCredential {
            prompt: "test".to_string(),
            cache_id: "test-key".to_string(),
            cache_type: None,
        };

        let response = daemon.handle_request(request, cache).await;
        match response {
            Response::Credential { value } => {
                assert_eq!(value.expose_secret(), "secret");
            }
            _ => panic!("Expected credential response after confirmation"),
        }
    }

    #[tokio::test]
    async fn handle_confirm_credential_not_found() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(socket);

        // Try to confirm non-existent credential
        let cache = Arc::clone(daemon.cache());
        let request = Request::ConfirmCredential {
            cache_id: "nonexistent".to_string(),
        };

        let response = daemon.handle_request(request, cache).await;
        match response {
            Response::Error { code, .. } => {
                assert_eq!(code, ErrorCode::NotFound);
            }
            _ => panic!("Expected error response"),
        }
    }

    #[tokio::test]
    async fn get_credential_returns_unconfirmed() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let socket = ManualSocketProvider::new(&socket_path);
        let daemon = Daemon::new(socket);

        // Store an unconfirmed credential directly in cache
        {
            let mut cache = daemon.cache().lock().await;
            cache.insert(
                "test-key",
                SecretString::from("test-pin"),
                Duration::from_secs(3600),
                CacheType::Ssh,
                false, // Unconfirmed
            );
        }

        // GetCredential should return UnconfirmedCredential
        let cache = Arc::clone(daemon.cache());
        let request = Request::GetCredential {
            prompt: "test".to_string(),
            cache_id: "test-key".to_string(),
            cache_type: None,
        };

        let response = daemon.handle_request(request, cache).await;
        match response {
            Response::UnconfirmedCredential {
                cache_id,
                cache_type,
                value,
            } => {
                assert_eq!(cache_id, "test-key");
                assert_eq!(cache_type, CacheType::Ssh);
                assert_eq!(value.expose_secret(), "test-pin");
            }
            _ => panic!("Expected UnconfirmedCredential response"),
        }

        // Verify the unconfirmed credential is still there (not removed)
        let cache = daemon.cache().lock().await;
        assert!(cache.get_any("test-key").is_some());
    }
}
