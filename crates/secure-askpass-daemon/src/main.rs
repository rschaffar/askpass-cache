//! secure-askpass-daemon - Main entry point.
//!
//! This is the main daemon process that handles credential caching.
//! It does NOT display any UI prompts - that's the client's job.
//!
//! # Architecture
//!
//! The daemon only manages the credential cache:
//! - Receives GetCredential requests and returns cached values or CacheMiss
//! - Receives StoreCredential requests to cache values after client prompts user
//! - Handles ClearCache requests
//!
//! The askpass-client binary handles all UI prompts (GTK4 dialogs) and
//! inherits the display environment from the calling process (SSH, Git, etc).

use anyhow::Result;
use secure_askpass_core::SocketProvider;
use secure_askpass_daemon::{Daemon, SystemdSocketProvider};
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

fn setup_logging() {
    // Set up tracing with environment filter
    // Use RUST_LOG=debug for verbose output
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true))
        .with(filter)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting secure-askpass-daemon"
    );

    let socket_provider = SystemdSocketProvider::new();

    // Log socket path
    if let Some(path) = SocketProvider::socket_path(&socket_provider) {
        info!(path = %path.display(), "Socket path");
    }

    // Create and run daemon
    let daemon = Daemon::new(socket_provider);

    info!("Daemon starting...");
    if let Err(e) = daemon.run().await {
        error!(error = %e, "Daemon error");
        return Err(e);
    }

    Ok(())
}
