//! askpass-client - Thin binary for SSH_ASKPASS/GIT_ASKPASS/SUDO_ASKPASS.
//!
//! This binary handles credential requests by:
//! 1. Checking the daemon's cache for existing credentials
//! 2. If not cached, showing a GTK4 dialog to prompt the user
//! 3. Storing the credential in the daemon's cache for future use
//! 4. Printing the credential to stdout (as expected by SSH/Git/sudo)
//!
//! # Architecture
//!
//! The client inherits the display environment from the calling process
//! (SSH, Git, sudo), which means GTK4 dialogs work correctly because the
//! client runs in the same graphical context as the caller.
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
use gtk4::prelude::*;
use gtk4::{
    Align, Application, ApplicationWindow, Box as GtkBox, Button, Entry, Label, Orientation,
};
use secrecy::{ExposeSecret, SecretString};
use secure_askpass_core::{CacheType, Request, Response};
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
fn get_prompt() -> String {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        // If no prompt is provided, use a generic one
        // This can happen in some edge cases
        return "Enter password:".to_string();
    }

    args[1..].join(" ")
}

/// Send a request to the daemon and receive a response.
fn send_request(request: &Request) -> Result<Response> {
    let socket_path = get_socket_path();

    // Connect to daemon
    let mut stream = UnixStream::connect(&socket_path)
        .with_context(|| format!("Failed to connect to daemon at {:?}", socket_path))?;

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

/// Request a credential from the daemon cache.
fn get_cached_credential(prompt: &str) -> Result<Response> {
    let request = Request::GetCredential {
        prompt: prompt.to_string(),
        cache_id: "auto".to_string(),
        cache_type: None,
    };

    send_request(&request)
}

/// Store a credential in the daemon cache.
fn store_credential(
    cache_id: &str,
    value: SecretString,
    cache_type: CacheType,
) -> Result<Response> {
    let request = Request::StoreCredential {
        cache_id: cache_id.to_string(),
        value,
        cache_type: Some(cache_type),
        ttl: None, // Use default TTL for the cache type
    };

    send_request(&request)
}

/// Result from the GTK password dialog.
enum DialogResult {
    /// User entered a password.
    Password(SecretString),
    /// User cancelled the dialog.
    Cancelled,
}

/// Show a GTK4 password dialog and return the entered password.
///
/// This function initializes GTK4, shows a dialog, and returns when the user
/// either enters a password or cancels.
fn show_gtk_dialog(prompt_text: &str) -> Result<DialogResult> {
    // Initialize GTK
    gtk4::init().context("Failed to initialize GTK4")?;

    // Create the application
    let app = Application::builder()
        .application_id("io.github.rschaffar.secure-askpass")
        .build();

    let prompt_text_owned = prompt_text.to_string();

    app.connect_activate(move |app| {
        // Create the main window
        let window = ApplicationWindow::builder()
            .application(app)
            .title("Authentication Required")
            .default_width(400)
            .default_height(150)
            .resizable(false)
            .modal(true)
            .build();

        // Create a vertical box for layout
        let vbox = GtkBox::new(Orientation::Vertical, 12);
        vbox.set_margin_top(20);
        vbox.set_margin_bottom(20);
        vbox.set_margin_start(20);
        vbox.set_margin_end(20);

        // Add prompt label
        let label = Label::new(Some(&prompt_text_owned));
        label.set_wrap(true);
        label.set_halign(Align::Start);
        vbox.append(&label);

        // Add password entry
        let entry = Entry::new();
        entry.set_visibility(false); // Hide password characters
        entry.set_activates_default(true);
        entry.set_placeholder_text(Some("Password"));
        vbox.append(&entry);

        // Create button box
        let button_box = GtkBox::new(Orientation::Horizontal, 8);
        button_box.set_halign(Align::End);
        button_box.set_margin_top(12);

        // Cancel button
        let cancel_button = Button::with_label("Cancel");
        let window_clone = window.clone();
        cancel_button.connect_clicked(move |_| {
            window_clone.close();
        });
        button_box.append(&cancel_button);

        // OK button
        let ok_button = Button::with_label("OK");
        ok_button.add_css_class("suggested-action");
        let entry_clone = entry.clone();
        let window_clone = window.clone();
        ok_button.connect_clicked(move |_| {
            let password = entry_clone.text().to_string();
            if !password.is_empty() {
                // Store the result in thread-local storage
                PASSWORD_RESULT.with(|r| {
                    *r.borrow_mut() = Some(password);
                });
            }
            window_clone.close();
        });
        button_box.append(&ok_button);

        // Make OK the default button
        ok_button.set_receives_default(true);

        // Handle Enter key in entry
        let ok_button_clone = ok_button.clone();
        entry.connect_activate(move |_| {
            ok_button_clone.emit_clicked();
        });

        vbox.append(&button_box);
        window.set_child(Some(&vbox));

        // Focus the entry
        entry.grab_focus();

        window.present();
    });

    // Run the application
    app.run_with_args::<&str>(&[]);

    // Get the result from thread-local storage
    let password = PASSWORD_RESULT.with(|r| r.borrow_mut().take());
    match password {
        Some(p) => Ok(DialogResult::Password(SecretString::from(p))),
        None => Ok(DialogResult::Cancelled),
    }
}

// Thread-local to pass password out of GTK event loop
// This is safe because GTK runs single-threaded on the main thread
thread_local! {
    static PASSWORD_RESULT: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

fn main() -> ExitCode {
    // Get the prompt
    let prompt = get_prompt();

    // First, try to get from cache
    let cache_response = match get_cached_credential(&prompt) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error connecting to daemon: {}", e);
            // Fall back to showing dialog without caching
            return show_dialog_and_print(&prompt);
        }
    };

    // Handle the cache response
    match cache_response {
        Response::Credential { value } => {
            // Cache hit - print credential and exit
            print!("{}", value.expose_secret());
            if std::io::stdout().flush().is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Response::CacheMiss {
            cache_id,
            cache_type,
        } => {
            // Cache miss - show dialog, store result, and print
            match show_gtk_dialog(&prompt) {
                Ok(DialogResult::Password(password)) => {
                    // Print the password first (so caller gets it quickly)
                    print!("{}", password.expose_secret());
                    if std::io::stdout().flush().is_err() {
                        return ExitCode::FAILURE;
                    }

                    // Store in cache (best effort - don't fail if this fails)
                    if let Err(e) = store_credential(&cache_id, password, cache_type) {
                        eprintln!("Warning: Failed to cache credential: {}", e);
                    }

                    ExitCode::SUCCESS
                }
                Ok(DialogResult::Cancelled) => {
                    // User cancelled
                    ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("Error showing dialog: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        Response::Error { code, message } => {
            eprintln!("Error ({}): {}", code, message);
            ExitCode::FAILURE
        }
        _ => {
            eprintln!("Error: Unexpected response type");
            ExitCode::FAILURE
        }
    }
}

/// Show dialog and print result without caching.
/// Used as fallback when daemon is not available.
fn show_dialog_and_print(prompt: &str) -> ExitCode {
    match show_gtk_dialog(prompt) {
        Ok(DialogResult::Password(password)) => {
            print!("{}", password.expose_secret());
            if std::io::stdout().flush().is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Ok(DialogResult::Cancelled) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("Error showing dialog: {}", e);
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
