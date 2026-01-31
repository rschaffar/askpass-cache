//! Manual socket binding provider.
//!
//! This module provides a simple socket provider that manually binds to a
//! Unix socket path. It's primarily used for development and testing when
//! systemd socket activation is not available.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use secure_askpass_core::{SocketError, SocketProvider};
use tokio::net::UnixListener;
use tracing::debug;

/// Socket provider that manually binds to a Unix socket.
///
/// This is the simplest socket provider, useful for development and testing.
pub struct ManualSocketProvider {
    /// Path to the Unix socket.
    path: PathBuf,
}

impl ManualSocketProvider {
    /// Create a new manual socket provider with the given path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Bind the socket.
    async fn bind(&self) -> Result<UnixListener, SocketError> {
        // Create parent directory if needed
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(SocketError::DirectoryCreationFailed)?;
                debug!(path = %parent.display(), "Created socket directory");
            }
        }

        // Remove existing socket if present
        if self.path.exists() {
            std::fs::remove_file(&self.path).map_err(|e| {
                SocketError::BindFailed(std::io::Error::other(format!(
                    "Failed to remove existing socket: {}",
                    e
                )))
            })?;
            debug!(path = %self.path.display(), "Removed existing socket");
        }

        // Bind the socket
        let listener = UnixListener::bind(&self.path).map_err(SocketError::BindFailed)?;

        // Set permissions to 0600 (owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.path, perms).map_err(|e| {
                SocketError::BindFailed(std::io::Error::other(format!(
                    "Failed to set socket permissions: {}",
                    e
                )))
            })?;
        }

        debug!(path = %self.path.display(), "Socket bound successfully");
        Ok(listener)
    }
}

impl Default for ManualSocketProvider {
    fn default() -> Self {
        Self::new(super::default_socket_path())
    }
}

impl SocketProvider for ManualSocketProvider {
    fn listen(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<UnixListener, SocketError>> + Send + '_>> {
        Box::pin(self.bind())
    }

    fn socket_path(&self) -> Option<&Path> {
        Some(&self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_creates_socket() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let provider = ManualSocketProvider::new(&socket_path);
        let _listener = provider.listen().await.unwrap();

        assert!(socket_path.exists());
    }

    #[tokio::test]
    async fn bind_creates_parent_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("subdir").join("test.sock");

        let provider = ManualSocketProvider::new(&socket_path);
        let _listener = provider.listen().await.unwrap();

        assert!(socket_path.exists());
        assert!(socket_path.parent().unwrap().exists());
    }

    #[tokio::test]
    async fn bind_replaces_existing_socket() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        // Create first socket
        let provider = ManualSocketProvider::new(&socket_path);
        let listener1 = provider.listen().await.unwrap();
        drop(listener1);

        // Should be able to bind again
        let _listener2 = provider.listen().await.unwrap();
        assert!(socket_path.exists());
    }

    #[tokio::test]
    async fn socket_has_correct_permissions() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let provider = ManualSocketProvider::new(&socket_path);
        let _listener = provider.listen().await.unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&socket_path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn socket_path_returns_path() {
        let path = PathBuf::from("/tmp/test.sock");
        let provider = ManualSocketProvider::new(&path);
        assert_eq!(provider.socket_path(), Some(path.as_path()));
    }

    #[test]
    fn default_uses_runtime_dir() {
        let provider = ManualSocketProvider::default();
        let path = provider.socket_path().unwrap();
        // Should end with secure-askpass/socket
        assert!(path.ends_with("socket"));
        assert!(path.parent().unwrap().ends_with("secure-askpass"));
    }
}
