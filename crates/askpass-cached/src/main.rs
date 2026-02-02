//! askpass-cached - Main entry point.
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

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser};

use askpass_cache_core::{Config, SocketProvider};
use askpass_cached::{Daemon, ManualSocketProvider, SystemdSocketProvider};

use tracing::{debug, error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Secure credential caching daemon for SSH_ASKPASS, GIT_ASKPASS, SUDO_ASKPASS.
#[derive(Parser)]
#[command(name = "askpass-cached")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to config file [default: ~/.config/askpass-cache/config.toml]
    #[arg(short, long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Path to Unix socket (forces manual binding, ignores systemd)
    #[arg(short, long, value_name = "PATH")]
    socket: Option<PathBuf>,

    /// Increase log verbosity (-v = debug, -vv = trace)
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,

    /// Only show errors
    #[arg(short, long)]
    quiet: bool,
}

fn setup_logging(level: &str) {
    // Set up tracing with environment filter
    // Use RUST_LOG=debug for verbose output, or CLI flags
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    // Check if running under systemd (JOURNAL_STREAM is set when stdout/stderr go to journal)
    if std::env::var("JOURNAL_STREAM").is_ok() {
        // Use journald for proper log levels in systemctl status / journalctl
        if let Ok(journald_layer) = tracing_journald::layer() {
            tracing_subscriber::registry()
                .with(journald_layer)
                .with(filter)
                .init();
            return;
        }
    }

    // Fallback to stderr (for development or non-systemd environments)
    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true))
        .with(filter)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Determine log level from CLI flags
    let log_level = if cli.quiet {
        "error"
    } else {
        match cli.verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        }
    };
    setup_logging(log_level);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting askpass-cached"
    );

    // Load configuration
    let config = match &cli.config {
        Some(path) => {
            info!(path = %path.display(), "Loading configuration from specified path");
            Config::load_from(path).context("Failed to load configuration")?
        }
        None => {
            let config = Config::load().context("Failed to load configuration")?;
            if let Some(path) = Config::default_path() {
                if path.exists() {
                    info!(path = %path.display(), "Loaded configuration");
                } else {
                    debug!("No config file found, using defaults");
                }
            }
            config
        }
    };

    // Run daemon with appropriate socket provider
    // Use match arms with concrete types to avoid Box<dyn SocketProvider>
    match &cli.socket {
        Some(path) => {
            info!(path = %path.display(), "Using manual socket binding (--socket specified)");
            let provider = ManualSocketProvider::new(path);
            run_daemon(provider, config).await
        }
        None => {
            if std::env::var("LISTEN_FDS").is_ok() {
                info!("Using systemd socket activation");
                let provider = SystemdSocketProvider::new();
                run_daemon(provider, config).await
            } else {
                info!("Using manual socket binding");
                let provider = ManualSocketProvider::default();
                run_daemon(provider, config).await
            }
        }
    }
}

/// Run the daemon with the given socket provider.
async fn run_daemon<S: SocketProvider>(socket_provider: S, config: Config) -> Result<()> {
    if let Some(path) = socket_provider.socket_path() {
        info!(path = %path.display(), "Socket path");
    }

    let daemon = Daemon::with_config(socket_provider, config);

    info!("Daemon starting...");
    if let Err(e) = daemon.run().await {
        error!(error = %e, "Daemon error");
        return Err(e);
    }

    Ok(())
}
