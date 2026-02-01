//! askpass-cache-ctl - Control utility for the secure-askpass credential cache.
//!
//! This utility allows you to:
//! - List cached credentials (metadata only, no secrets)
//! - Delete cached credentials by ID, type, or all
//! - Check if the daemon is running
//!
//! # Usage
//!
//! ```bash
//! # List all cached credentials
//! askpass-cache-ctl list
//!
//! # Delete by short ID
//! askpass-cache-ctl delete a7f3b2c1
//!
//! # Delete all SSH credentials
//! askpass-cache-ctl delete --type ssh
//!
//! # Delete all credentials
//! askpass-cache-ctl delete --all
//!
//! # Check daemon status
//! askpass-cache-ctl ping
//! ```

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use secure_askpass_core::{short_id, CacheType, Request, Response};

/// Control utility for the secure-askpass credential cache.
#[derive(Parser)]
#[command(name = "askpass-cache-ctl")]
#[command(about = "Control the secure-askpass credential cache")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List cached credentials (metadata only, no secrets)
    #[command(alias = "ls")]
    List,

    /// Delete cached credentials
    #[command(alias = "rm")]
    Delete {
        /// Short ID or full cache_id to delete (omit for --all or --type)
        target: Option<String>,

        /// Delete all cached credentials
        #[arg(long, short = 'a')]
        all: bool,

        /// Delete only credentials of this type (ssh, git, sudo, custom)
        #[arg(long, short = 't', value_name = "TYPE")]
        r#type: Option<String>,
    },

    /// Check if daemon is running
    #[command(alias = "status")]
    Ping,
}

/// Get the socket path.
fn get_socket_path() -> PathBuf {
    if let Some(runtime_dir) = dirs::runtime_dir() {
        runtime_dir.join("secure-askpass").join("socket")
    } else {
        // Fallback for systems without XDG_RUNTIME_DIR
        let uid = unsafe { libc::getuid() };
        PathBuf::from(format!("/tmp/secure-askpass-{}/socket", uid))
    }
}

/// Send a request to the daemon and receive a response.
fn send_request(request: &Request) -> Result<Response> {
    let socket_path = get_socket_path();

    let mut stream = UnixStream::connect(&socket_path)
        .with_context(|| format!("Failed to connect to daemon at {:?}", socket_path))?;

    let request_json = request
        .to_json_line()
        .context("Failed to serialize request")?;
    stream
        .write_all(request_json.as_bytes())
        .context("Failed to send request")?;
    stream.flush().context("Failed to flush request")?;

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .context("Failed to read response")?;

    Response::parse(response_line.trim()).context("Failed to parse response")
}

/// Format TTL as human-readable string.
fn format_ttl(secs: Option<u64>) -> String {
    match secs {
        None => "expired".to_string(),
        Some(s) if s < 60 => format!("{}s", s),
        Some(s) if s < 3600 => format!("{}m {}s", s / 60, s % 60),
        Some(s) => format!("{}h {}m", s / 3600, (s % 3600) / 60),
    }
}

/// Handle the list command.
fn cmd_list() -> Result<ExitCode> {
    let response = send_request(&Request::ListCache)?;

    match response {
        Response::CacheEntries { entries } => {
            if entries.is_empty() {
                println!("No cached credentials.");
                return Ok(ExitCode::SUCCESS);
            }

            // Print header
            println!("{:<10} {:<8} {:<45} TTL", "ID", "TYPE", "CACHE ID");
            println!("{}", "-".repeat(75));

            // Print entries
            for entry in entries {
                // Truncate cache_id if too long
                let cache_id_display = if entry.cache_id.len() > 43 {
                    format!("{}...", &entry.cache_id[..40])
                } else {
                    entry.cache_id.clone()
                };

                println!(
                    "{:<10} {:<8} {:<45} {}",
                    entry.id,
                    entry.cache_type.to_string().to_lowercase(),
                    cache_id_display,
                    format_ttl(entry.ttl_remaining_secs)
                );
            }

            Ok(ExitCode::SUCCESS)
        }
        Response::Error { code, message } => {
            eprintln!("Error ({}): {}", code, message);
            Ok(ExitCode::FAILURE)
        }
        _ => {
            eprintln!("Unexpected response from daemon");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Handle the delete command.
fn cmd_delete(target: Option<String>, all: bool, type_filter: Option<String>) -> Result<ExitCode> {
    // Validate arguments
    if target.is_some() && (all || type_filter.is_some()) {
        eprintln!("Error: Cannot specify both a target ID and --all or --type");
        return Ok(ExitCode::FAILURE);
    }

    if target.is_none() && !all && type_filter.is_none() {
        eprintln!("Error: Must specify a target ID, --all, or --type");
        eprintln!("Usage: askpass-cache-ctl delete <ID>");
        eprintln!("       askpass-cache-ctl delete --all");
        eprintln!("       askpass-cache-ctl delete --type ssh");
        return Ok(ExitCode::FAILURE);
    }

    // Parse cache type if specified
    let cache_type = if let Some(ref type_str) = type_filter {
        let ct = match type_str.to_lowercase().as_str() {
            "ssh" => CacheType::Ssh,
            "git" => CacheType::Git,
            "sudo" => CacheType::Sudo,
            "custom" => CacheType::Custom,
            _ => {
                eprintln!(
                    "Error: Unknown cache type '{}'. Valid types: ssh, git, sudo, custom",
                    type_str
                );
                return Ok(ExitCode::FAILURE);
            }
        };
        Some(ct)
    } else {
        None
    };

    // If target is a short ID, we need to resolve it first
    let cache_id = if let Some(ref t) = target {
        // Check if it looks like a short ID (8 hex chars)
        if t.len() == 8 && t.chars().all(|c| c.is_ascii_hexdigit()) {
            // It's a short ID, need to find the full cache_id
            resolve_short_id(t)?
        } else {
            // Assume it's a full cache_id
            t.clone()
        }
    } else {
        "all".to_string()
    };

    let request = Request::ClearCache {
        cache_id,
        cache_type,
    };

    let response = send_request(&request)?;

    match response {
        Response::CacheCleared { count } => {
            if count == 0 {
                println!("No matching entries found.");
            } else if count == 1 {
                println!("Deleted 1 entry.");
            } else {
                println!("Deleted {} entries.", count);
            }
            Ok(ExitCode::SUCCESS)
        }
        Response::Error { code, message } => {
            eprintln!("Error ({}): {}", code, message);
            Ok(ExitCode::FAILURE)
        }
        _ => {
            eprintln!("Unexpected response from daemon");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Resolve a short ID to a full cache_id by listing the cache.
fn resolve_short_id(short: &str) -> Result<String> {
    let response = send_request(&Request::ListCache)?;

    match response {
        Response::CacheEntries { entries } => {
            // Find entry with matching short ID
            let matches: Vec<_> = entries
                .iter()
                .filter(|e| e.id == short || short_id(&e.cache_id) == short)
                .collect();

            match matches.len() {
                0 => {
                    anyhow::bail!("No cache entry found with ID '{}'", short);
                }
                1 => Ok(matches[0].cache_id.clone()),
                _ => {
                    // This shouldn't happen with proper hashing, but handle it
                    anyhow::bail!(
                        "Multiple entries match ID '{}'. Use full cache_id instead.",
                        short
                    );
                }
            }
        }
        Response::Error { code, message } => {
            anyhow::bail!("Error listing cache ({}): {}", code, message);
        }
        _ => {
            anyhow::bail!("Unexpected response from daemon");
        }
    }
}

/// Handle the ping command.
fn cmd_ping() -> Result<ExitCode> {
    let response = send_request(&Request::Ping)?;

    match response {
        Response::Pong => {
            println!("Daemon is running.");
            Ok(ExitCode::SUCCESS)
        }
        Response::Error { code, message } => {
            eprintln!("Error ({}): {}", code, message);
            Ok(ExitCode::FAILURE)
        }
        _ => {
            eprintln!("Unexpected response from daemon");
            Ok(ExitCode::FAILURE)
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::List => cmd_list(),
        Commands::Delete {
            target,
            all,
            r#type,
        } => cmd_delete(target, all, r#type),
        Commands::Ping => cmd_ping(),
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_ttl_seconds() {
        assert_eq!(format_ttl(Some(30)), "30s");
        assert_eq!(format_ttl(Some(59)), "59s");
    }

    #[test]
    fn format_ttl_minutes() {
        assert_eq!(format_ttl(Some(60)), "1m 0s");
        assert_eq!(format_ttl(Some(90)), "1m 30s");
        assert_eq!(format_ttl(Some(3599)), "59m 59s");
    }

    #[test]
    fn format_ttl_hours() {
        assert_eq!(format_ttl(Some(3600)), "1h 0m");
        assert_eq!(format_ttl(Some(5400)), "1h 30m");
        assert_eq!(format_ttl(Some(7200)), "2h 0m");
    }

    #[test]
    fn format_ttl_expired() {
        assert_eq!(format_ttl(None), "expired");
    }

    #[test]
    fn socket_path_uses_runtime_dir() {
        let path = get_socket_path();
        assert!(path.ends_with("socket"));
        assert!(path.parent().unwrap().ends_with("secure-askpass"));
    }
}
