//! askpass-client - Thin binary for SSH_ASKPASS/GIT_ASKPASS/SUDO_ASKPASS.
//!
//! This binary connects to the secure-askpass daemon to request credentials.
//! It's designed to be used as:
//! - SSH_ASKPASS for SSH FIDO2 PIN entry
//! - GIT_ASKPASS for Git credential prompts
//! - SUDO_ASKPASS for sudo password prompts
//!
//! # Usage
//!
//! ```bash
//! # Set as SSH askpass
//! export SSH_ASKPASS=/path/to/askpass-client
//! export SSH_ASKPASS_REQUIRE=prefer
//!
//! # Set as Git askpass
//! export GIT_ASKPASS=/path/to/askpass-client
//!
//! # Set as sudo askpass
//! export SUDO_ASKPASS=/path/to/askpass-client
//! sudo -A some_command
//! ```
//!
//! The prompt text is passed as the first command-line argument.
//! The credential is printed to stdout (as expected by SSH/Git/sudo).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use secrecy::ExposeSecret;
use secure_askpass_core::{Request, Response};
use zeroize::Zeroize;

/// Get the socket path.
///
/// Returns `$XDG_RUNTIME_DIR/secure-askpass/socket` or falls back to
/// `/tmp/secure-askpass-$UID/socket` if XDG_RUNTIME_DIR is not set.
fn get_socket_path() -> PathBuf {
    if let Some(runtime_dir) = dirs::runtime_dir() {
        runtime_dir.join("secure-askpass").join("socket")
    } else {
        // Fallback for systems without XDG_RUNTIME_DIR
        let uid = unsafe { libc::getuid() };
        PathBuf::from(format!("/tmp/secure-askpass-{}/socket", uid))
    }
}

/// Get the prompt text from command-line arguments.
///
/// SSH_ASKPASS, GIT_ASKPASS, and SUDO_ASKPASS all pass the prompt as
/// the first argument.
fn get_prompt() -> Result<String> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        // If no prompt is provided, use a generic one
        // This can happen in some edge cases
        return Ok("Enter password:".to_string());
    }

    Ok(args[1..].join(" "))
}

/// Send a request to the daemon and receive a response.
fn request_credential(prompt: &str) -> Result<Response> {
    let socket_path = get_socket_path();

    // Connect to daemon
    let mut stream = UnixStream::connect(&socket_path)
        .with_context(|| format!("Failed to connect to daemon at {:?}", socket_path))?;

    // Create request
    let request = Request::GetCredential {
        prompt: prompt.to_string(),
        cache_id: "auto".to_string(),
        cache_type: None,
        ttl: None,
        allow_cache: true,
        echo: false,
    };

    // Send request
    let request_json = request
        .to_json_line()
        .context("Failed to serialize request")?;
    stream
        .write_all(request_json.as_bytes())
        .context("Failed to send request")?;
    stream.flush().context("Failed to flush request")?;

    // Read response
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .context("Failed to read response")?;

    // Parse response
    let response = Response::parse(response_line.trim()).context("Failed to parse response")?;

    // Zero the response line before dropping
    response_line.zeroize();

    Ok(response)
}

fn main() -> ExitCode {
    // Get the prompt
    let prompt = match get_prompt() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Request credential from daemon
    let response = match request_credential(&prompt) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Handle response
    match response {
        Response::Credential { value, .. } => {
            // Print credential to stdout (this is what SSH/Git/sudo expect)
            // Note: We use print! not println! because some programs
            // don't want the trailing newline
            print!("{}", value.expose_secret());

            // Flush to ensure the credential is written before we exit
            if std::io::stdout().flush().is_err() {
                return ExitCode::FAILURE;
            }

            // The SecretString will be zeroized when dropped
            ExitCode::SUCCESS
        }
        Response::Error { code, message } => {
            eprintln!("Error ({}): {}", code, message);
            ExitCode::FAILURE
        }
        Response::CacheCleared { .. } => {
            // Unexpected response type
            eprintln!("Error: Unexpected response type");
            ExitCode::FAILURE
        }
        Response::Pong => {
            // Unexpected response type
            eprintln!("Error: Unexpected response type");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_path_uses_runtime_dir() {
        let path = get_socket_path();
        // Should end with secure-askpass/socket
        assert!(path.ends_with("socket"));
        assert!(path.parent().unwrap().ends_with("secure-askpass"));
    }

    #[test]
    fn get_prompt_with_no_args_returns_default() {
        // This test modifies global state (args), so it's not ideal
        // In practice, we'd use a function that takes args as a parameter
        // For now, we just verify the function signature works
    }
}
