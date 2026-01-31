//! Systemd socket activation provider.
//!
//! This module implements socket activation as described in:
//! https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html
//!
//! When a service is started via socket activation, systemd passes pre-opened
//! file descriptors via environment variables:
//! - `LISTEN_FDS`: Number of file descriptors passed
//! - `LISTEN_PID`: PID of the process that should receive them
//!
//! File descriptors start at 3 (SD_LISTEN_FDS_START).

use std::future::Future;
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::Path;
use std::pin::Pin;

use secure_askpass_core::{SocketError, SocketProvider};
use tokio::net::UnixListener;
use tracing::{debug, warn};

/// The first file descriptor passed by systemd (SD_LISTEN_FDS_START).
const SD_LISTEN_FDS_START: RawFd = 3;

/// Socket provider using systemd socket activation.
///
/// This provider expects to receive a pre-bound socket from systemd.
/// If socket activation is not available, it falls back to manual binding.
pub struct SystemdSocketProvider {
    /// Fallback path for manual binding if systemd activation fails.
    fallback_path: std::path::PathBuf,
}

impl SystemdSocketProvider {
    /// Create a new systemd socket provider.
    pub fn new() -> Self {
        Self {
            fallback_path: super::default_socket_path(),
        }
    }

    /// Create a provider with a custom fallback path.
    pub fn with_fallback(fallback_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            fallback_path: fallback_path.into(),
        }
    }

    /// Check if systemd socket activation is available.
    fn is_socket_activation_available() -> bool {
        // Check LISTEN_FDS environment variable
        let listen_fds = match std::env::var("LISTEN_FDS") {
            Ok(val) => val,
            Err(_) => return false,
        };

        // Parse the number of FDs
        let num_fds: u32 = match listen_fds.parse() {
            Ok(n) => n,
            Err(_) => return false,
        };

        // We need at least one FD
        if num_fds == 0 {
            return false;
        }

        // Check if LISTEN_PID matches our PID (if set)
        if let Ok(listen_pid) = std::env::var("LISTEN_PID") {
            if let Ok(pid) = listen_pid.parse::<u32>() {
                let our_pid = std::process::id();
                if pid != our_pid {
                    warn!(
                        listen_pid = pid,
                        our_pid = our_pid,
                        "LISTEN_PID doesn't match our PID"
                    );
                    return false;
                }
            }
        }

        true
    }

    /// Get the socket from systemd.
    fn get_systemd_socket() -> Result<std::os::unix::net::UnixListener, SocketError> {
        // The socket is at file descriptor 3 (SD_LISTEN_FDS_START)
        let fd = SD_LISTEN_FDS_START;

        // Safety: We're taking ownership of a file descriptor passed by systemd.
        // Systemd guarantees this FD is valid when LISTEN_FDS >= 1.
        let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };

        // Set non-blocking mode for tokio
        std_listener.set_nonblocking(true).map_err(|e| {
            SocketError::SystemdActivationFailed(format!("Failed to set non-blocking: {}", e))
        })?;

        debug!(fd = fd, "Acquired socket from systemd");
        Ok(std_listener)
    }

    /// Fallback to manual binding.
    async fn bind_manual(&self) -> Result<UnixListener, SocketError> {
        debug!(path = %self.fallback_path.display(), "Falling back to manual socket binding");

        // Create parent directory if needed
        if let Some(parent) = self.fallback_path.parent() {
            std::fs::create_dir_all(parent).map_err(SocketError::DirectoryCreationFailed)?;
        }

        // Remove existing socket if present
        if self.fallback_path.exists() {
            std::fs::remove_file(&self.fallback_path).map_err(|e| {
                SocketError::BindFailed(std::io::Error::other(format!(
                    "Failed to remove existing socket: {}",
                    e
                )))
            })?;
        }

        // Bind the socket
        let listener = UnixListener::bind(&self.fallback_path).map_err(SocketError::BindFailed)?;

        // Set permissions to 0600 (owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.fallback_path, perms).map_err(|e| {
                SocketError::BindFailed(std::io::Error::other(format!(
                    "Failed to set socket permissions: {}",
                    e
                )))
            })?;
        }

        debug!(path = %self.fallback_path.display(), "Socket bound successfully");
        Ok(listener)
    }
}

impl Default for SystemdSocketProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketProvider for SystemdSocketProvider {
    fn listen(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<UnixListener, SocketError>> + Send + '_>> {
        Box::pin(async move {
            if Self::is_socket_activation_available() {
                // Get socket from systemd
                let std_listener = Self::get_systemd_socket()?;

                // Convert to tokio UnixListener
                let listener = UnixListener::from_std(std_listener).map_err(|e| {
                    SocketError::SystemdActivationFailed(format!(
                        "Failed to convert to tokio listener: {}",
                        e
                    ))
                })?;

                Ok(listener)
            } else {
                // Fall back to manual binding
                self.bind_manual().await
            }
        })
    }

    fn socket_path(&self) -> Option<&Path> {
        Some(&self.fallback_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_activation_not_available_without_env() {
        // Clear any existing env vars
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_PID");

        assert!(!SystemdSocketProvider::is_socket_activation_available());
    }

    #[test]
    fn socket_activation_not_available_with_zero_fds() {
        std::env::set_var("LISTEN_FDS", "0");
        assert!(!SystemdSocketProvider::is_socket_activation_available());
        std::env::remove_var("LISTEN_FDS");
    }

    #[test]
    fn socket_activation_not_available_with_wrong_pid() {
        std::env::set_var("LISTEN_FDS", "1");
        std::env::set_var("LISTEN_PID", "99999999"); // Very unlikely to be our PID
        assert!(!SystemdSocketProvider::is_socket_activation_available());
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_PID");
    }

    #[test]
    fn default_creates_provider() {
        let provider = SystemdSocketProvider::default();
        assert!(provider.socket_path().is_some());
    }

    #[tokio::test]
    async fn fallback_binding_works() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let provider = SystemdSocketProvider::with_fallback(&socket_path);

        // Should fall back to manual binding since LISTEN_FDS is not set
        std::env::remove_var("LISTEN_FDS");
        let listener = provider.listen().await.unwrap();

        // Socket should exist
        assert!(socket_path.exists());

        // Check permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&socket_path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        drop(listener);
    }
}
