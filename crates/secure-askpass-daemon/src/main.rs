//! secure-askpass-daemon - Main entry point.
//!
//! This is the main daemon process that handles credential caching
//! and password prompts for SSH_ASKPASS, GIT_ASKPASS, and SUDO_ASKPASS.
//!
//! # Environment Variables
//!
//! - `SECURE_ASKPASS_CLI=1` - Use CLI prompt instead of GTK4 (for testing/headless)
//! - `RUST_LOG=debug` - Enable verbose logging

use std::env;

use anyhow::Result;
use secure_askpass_core::SocketProvider;
use secure_askpass_daemon::{CliPasswordPrompt, Daemon, Gtk4PasswordPrompt, SystemdSocketProvider};
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

/// Check if CLI mode is enabled via environment variable.
fn use_cli_mode() -> bool {
    env::var("SECURE_ASKPASS_CLI")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let cli_mode = use_cli_mode();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        cli_mode = cli_mode,
        "Starting secure-askpass-daemon"
    );

    let socket_provider = SystemdSocketProvider::new();

    // Log socket path
    if let Some(path) = SocketProvider::socket_path(&socket_provider) {
        info!(path = %path.display(), "Socket path");
    }

    // Create and run daemon with appropriate prompt type
    if cli_mode {
        info!("Using CLI prompt (terminal-based)");
        let prompt = CliPasswordPrompt::new();
        let daemon = Daemon::new(prompt, socket_provider);

        info!("Daemon starting...");
        if let Err(e) = daemon.run().await {
            error!(error = %e, "Daemon error");
            return Err(e);
        }
    } else {
        info!("Using GTK4 prompt (GUI-based)");
        let prompt = Gtk4PasswordPrompt::new();
        let daemon = Daemon::new(prompt, socket_provider);

        info!("Daemon starting...");
        if let Err(e) = daemon.run().await {
            error!(error = %e, "Daemon error");
            return Err(e);
        }
    }

    Ok(())
}
