//! Socket provider implementations for the daemon.
//!
//! This module provides two socket provider implementations:
//!
//! - [`SystemdSocketProvider`]: Uses systemd socket activation (production)
//! - [`ManualSocketProvider`]: Binds socket manually (development/testing)
//!
//! Both implement the [`SocketProvider`] trait from `secure-askpass-core`.

mod manual;
mod systemd;

pub use manual::ManualSocketProvider;
pub use systemd::SystemdSocketProvider;

use secure_askpass_core::SocketProvider;

/// Create the default socket provider based on environment.
///
/// If `LISTEN_FDS` is set (systemd socket activation), returns a
/// [`SystemdSocketProvider`]. Otherwise, returns a [`ManualSocketProvider`].
pub fn default_provider() -> Box<dyn SocketProvider> {
    if std::env::var("LISTEN_FDS").is_ok() {
        tracing::info!("Using systemd socket activation");
        Box::new(SystemdSocketProvider::new())
    } else {
        tracing::info!("Using manual socket binding");
        Box::new(ManualSocketProvider::default())
    }
}

/// Get the default socket path.
///
/// Returns `$XDG_RUNTIME_DIR/secure-askpass/socket` or falls back to
/// `/tmp/secure-askpass-$UID/socket` if XDG_RUNTIME_DIR is not set.
pub fn default_socket_path() -> std::path::PathBuf {
    if let Some(runtime_dir) = dirs::runtime_dir() {
        runtime_dir.join("secure-askpass").join("socket")
    } else {
        // Fallback for systems without XDG_RUNTIME_DIR
        let uid = unsafe { libc::getuid() };
        std::path::PathBuf::from(format!("/tmp/secure-askpass-{}/socket", uid))
    }
}
