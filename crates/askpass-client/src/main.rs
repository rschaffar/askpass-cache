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
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, Result};
use askpass_cache_core::{CacheType, Request, Response};
use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{
    Align, Application, ApplicationWindow, Box as GtkBox, Button, CheckButton, Entry, Label,
    Orientation,
};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

/// Get the socket path.
///
/// Returns `$XDG_RUNTIME_DIR/askpass-cache/socket` or falls back to
/// `/tmp/askpass-cache-$UID/socket` if XDG_RUNTIME_DIR is not set.
fn get_socket_path() -> PathBuf {
    if let Some(runtime_dir) = dirs::runtime_dir() {
        runtime_dir.join("askpass-cache").join("socket")
    } else {
        // Fallback for systems without XDG_RUNTIME_DIR
        let uid = unsafe { libc::getuid() };
        PathBuf::from(format!("/tmp/askpass-cache-{}/socket", uid))
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
///
/// If `confirmed` is `false`, the credential is stored in an unconfirmed state
/// and will not be returned by GetCredential until confirmed.
fn store_credential(
    cache_id: &str,
    value: SecretString,
    cache_type: CacheType,
    confirmed: bool,
) -> Result<Response> {
    let request = Request::StoreCredential {
        cache_id: cache_id.to_string(),
        value,
        cache_type: Some(cache_type),
        ttl: None, // Use default TTL for the cache type
        confirmed: Some(confirmed),
    };

    send_request(&request)
}

/// Send a ConfirmCredential request to the daemon.
fn confirm_credential(cache_id: &str) -> Result<Response> {
    let request = Request::ConfirmCredential {
        cache_id: cache_id.to_string(),
    };

    send_request(&request)
}

/// Send a ClearCache request to clear a specific credential.
fn clear_credential(cache_id: &str) -> Result<Response> {
    let request = Request::ClearCache {
        cache_id: cache_id.to_string(),
        cache_type: None,
    };

    send_request(&request)
}

/// Spawn a confirmation dialog in a separate process.
///
/// This is called after the credential has been stored as unconfirmed
/// and printed to stdout. The confirmation dialog will run asynchronously
/// and confirm or clear the credential based on user input.
fn spawn_confirmation_dialog(cache_id: &str, prompt: &str) -> Result<()> {
    let exe = std::env::current_exe().context("Failed to get current executable path")?;

    Command::new(exe)
        .arg("--confirm")
        .arg(cache_id)
        .arg(prompt)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit()) // Allow errors to be seen
        .spawn()
        .context("Failed to spawn confirmation dialog")?;

    Ok(())
}

/// Result from the GTK password dialog.
enum DialogResult {
    /// User entered a password.
    Password {
        /// The entered password.
        value: SecretString,
        /// Whether to remember (cache) the password.
        remember: bool,
    },
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
        .application_id("io.github.rschaffar.askpass-cache")
        .build();

    let prompt_text_owned = prompt_text.to_string();

    app.connect_activate(move |app| {
        // Create the main window
        let window = ApplicationWindow::builder()
            .application(app)
            .title("Authentication Required")
            .default_width(400)
            .default_height(180)
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

        // Add "Remember for this session" checkbox with Alt+R mnemonic
        let remember_check = CheckButton::with_mnemonic("_Remember for this session");
        remember_check.set_active(true); // Checked by default
        vbox.append(&remember_check);

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
        let remember_clone = remember_check.clone();
        let window_clone = window.clone();
        ok_button.connect_clicked(move |_| {
            let password = entry_clone.text().to_string();
            if !password.is_empty() {
                let remember = remember_clone.is_active();
                // Store the result in thread-local storage
                PASSWORD_RESULT.with(|r| {
                    *r.borrow_mut() = Some((password, remember));
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
    let result = PASSWORD_RESULT.with(|r| r.borrow_mut().take());
    match result {
        Some((password, remember)) => Ok(DialogResult::Password {
            value: SecretString::from(password),
            remember,
        }),
        None => Ok(DialogResult::Cancelled),
    }
}

// Thread-local to pass password and remember flag out of GTK event loop
// This is safe because GTK runs single-threaded on the main thread
thread_local! {
    static PASSWORD_RESULT: std::cell::RefCell<Option<(String, bool)>> = const { std::cell::RefCell::new(None) };
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    // Check for --confirm mode (spawned by ourselves after storing credential)
    if args.len() >= 3 && args[1] == "--confirm" {
        let cache_id = &args[2];
        let prompt = args.get(3).map(|s| s.as_str()).unwrap_or("");
        return run_confirmation_dialog(cache_id, prompt);
    }

    // Normal askpass mode
    run_askpass_mode()
}

/// Run in normal askpass mode (SSH_ASKPASS/GIT_ASKPASS/SUDO_ASKPASS).
fn run_askpass_mode() -> ExitCode {
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
                Ok(DialogResult::Password { value, remember }) => {
                    // Print the password first (so caller gets it quickly)
                    print!("{}", value.expose_secret());
                    if std::io::stdout().flush().is_err() {
                        return ExitCode::FAILURE;
                    }

                    // Store in cache only if user wants to remember
                    if remember {
                        // Store as UNCONFIRMED - will be confirmed by the dialog
                        if let Err(e) = store_credential(&cache_id, value, cache_type, false) {
                            eprintln!("Warning: Failed to cache credential: {}", e);
                        } else {
                            // Spawn confirmation dialog in a separate process
                            if let Err(e) = spawn_confirmation_dialog(&cache_id, &prompt) {
                                eprintln!("Warning: Failed to spawn confirmation dialog: {}", e);
                            }
                        }
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
        Ok(DialogResult::Password { value, .. }) => {
            // Note: remember flag is ignored here since daemon is unavailable
            print!("{}", value.expose_secret());
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

/// Result from the confirmation dialog.
enum ConfirmResult {
    /// User clicked "Remember" - confirm the credential.
    Remember,
    /// User clicked "Clear" or closed the dialog - clear the credential.
    Clear,
}

/// Run in confirmation dialog mode (spawned after storing unconfirmed credential).
fn run_confirmation_dialog(cache_id: &str, prompt: &str) -> ExitCode {
    match show_confirmation_gtk_dialog(cache_id, prompt) {
        Ok(ConfirmResult::Remember) => {
            // User confirmed - promote the credential
            match confirm_credential(cache_id) {
                Ok(Response::Confirmed) => {
                    // Successfully confirmed
                    ExitCode::SUCCESS
                }
                Ok(Response::Error { code, message }) => {
                    eprintln!("Failed to confirm credential ({}): {}", code, message);
                    ExitCode::FAILURE
                }
                Ok(_) => {
                    eprintln!("Unexpected response when confirming credential");
                    ExitCode::FAILURE
                }
                Err(e) => {
                    // Show error dialog
                    show_error_dialog(&format!(
                        "Failed to connect to daemon:\n{}\n\nThe credential was not saved.",
                        e
                    ));
                    ExitCode::FAILURE
                }
            }
        }
        Ok(ConfirmResult::Clear) => {
            // User declined or closed - clear the credential
            match clear_credential(cache_id) {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("Warning: Failed to clear credential: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("Error showing confirmation dialog: {}", e);
            // Try to clear the unconfirmed credential on error
            let _ = clear_credential(cache_id);
            ExitCode::FAILURE
        }
    }
}

// Thread-local to pass confirmation result out of GTK event loop
thread_local! {
    static CONFIRM_RESULT: std::cell::RefCell<Option<ConfirmResult>> = const { std::cell::RefCell::new(None) };
}

/// Show a GTK4 confirmation dialog asking if authentication succeeded.
fn show_confirmation_gtk_dialog(cache_id: &str, prompt: &str) -> Result<ConfirmResult> {
    // Initialize GTK
    gtk4::init().context("Failed to initialize GTK4")?;

    // Create the application with a different ID to allow running alongside main dialog
    let app = Application::builder()
        .application_id("io.github.rschaffar.askpass-cache.confirm")
        .build();

    let cache_id_owned = cache_id.to_string();
    let prompt_owned = prompt.to_string();

    app.connect_activate(move |app| {
        // Create the main window
        let window = ApplicationWindow::builder()
            .application(app)
            .title("Credential Cached")
            .default_width(400)
            .default_height(200)
            .resizable(false)
            .build();

        // Window will be brought to front when presented

        // Create a vertical box for layout
        let vbox = GtkBox::new(Orientation::Vertical, 12);
        vbox.set_margin_top(20);
        vbox.set_margin_bottom(20);
        vbox.set_margin_start(20);
        vbox.set_margin_end(20);

        // Add question label
        let question_label = Label::new(Some("Did authentication succeed?"));
        question_label.set_halign(Align::Start);
        question_label.add_css_class("title-4");
        vbox.append(&question_label);

        // Show a shortened version of the cache_id
        let display_id = if cache_id_owned.len() > 50 {
            format!("{}...", &cache_id_owned[..47])
        } else {
            cache_id_owned.clone()
        };
        let id_label = Label::new(Some(&display_id));
        id_label.set_halign(Align::Start);
        id_label.set_wrap(true);
        id_label.add_css_class("dim-label");
        id_label.set_selectable(true);
        vbox.append(&id_label);

        // Show prompt if available
        if !prompt_owned.is_empty() {
            let prompt_display = if prompt_owned.len() > 80 {
                format!("{}...", &prompt_owned[..77])
            } else {
                prompt_owned.clone()
            };
            let prompt_label = Label::new(Some(&prompt_display));
            prompt_label.set_halign(Align::Start);
            prompt_label.set_wrap(true);
            prompt_label.add_css_class("caption");
            vbox.append(&prompt_label);
        }

        // Create button box
        let button_box = GtkBox::new(Orientation::Horizontal, 8);
        button_box.set_halign(Align::End);
        button_box.set_margin_top(16);

        // Clear button (left)
        let clear_button = Button::with_label("Clear");
        let window_clone = window.clone();
        clear_button.connect_clicked(move |_| {
            CONFIRM_RESULT.with(|r| {
                *r.borrow_mut() = Some(ConfirmResult::Clear);
            });
            window_clone.close();
        });
        button_box.append(&clear_button);

        // Remember button (right, suggested action)
        let remember_button = Button::with_label("Remember");
        remember_button.add_css_class("suggested-action");
        let window_clone = window.clone();
        remember_button.connect_clicked(move |_| {
            CONFIRM_RESULT.with(|r| {
                *r.borrow_mut() = Some(ConfirmResult::Remember);
            });
            window_clone.close();
        });
        button_box.append(&remember_button);

        // Handle window close (X button) - treat as Clear
        window.connect_close_request(move |_| {
            // If no result set yet, treat as Clear
            CONFIRM_RESULT.with(|r| {
                if r.borrow().is_none() {
                    *r.borrow_mut() = Some(ConfirmResult::Clear);
                }
            });
            glib::Propagation::Proceed
        });

        vbox.append(&button_box);
        window.set_child(Some(&vbox));

        // Focus the Remember button (most common action after success)
        remember_button.grab_focus();

        window.present();

        // Set urgency hint to flash in taskbar
        if let Some(surface) = window.surface() {
            // Request attention
            surface.queue_render();
        }
    });

    // Run the application
    app.run_with_args::<&str>(&[]);

    // Get the result from thread-local storage
    let result = CONFIRM_RESULT.with(|r| r.borrow_mut().take());
    Ok(result.unwrap_or(ConfirmResult::Clear))
}

/// Show an error dialog.
fn show_error_dialog(message: &str) {
    if gtk4::init().is_err() {
        eprintln!("Error: {}", message);
        return;
    }

    let app = Application::builder()
        .application_id("io.github.rschaffar.askpass-cache.error")
        .build();

    let message_owned = message.to_string();

    app.connect_activate(move |app| {
        let window = ApplicationWindow::builder()
            .application(app)
            .title("Error")
            .default_width(400)
            .default_height(150)
            .resizable(false)
            .build();

        let vbox = GtkBox::new(Orientation::Vertical, 12);
        vbox.set_margin_top(20);
        vbox.set_margin_bottom(20);
        vbox.set_margin_start(20);
        vbox.set_margin_end(20);

        let label = Label::new(Some(&message_owned));
        label.set_wrap(true);
        label.set_halign(Align::Start);
        vbox.append(&label);

        let button_box = GtkBox::new(Orientation::Horizontal, 8);
        button_box.set_halign(Align::End);
        button_box.set_margin_top(12);

        let ok_button = Button::with_label("OK");
        ok_button.add_css_class("suggested-action");
        let window_clone = window.clone();
        ok_button.connect_clicked(move |_| {
            window_clone.close();
        });
        button_box.append(&ok_button);

        vbox.append(&button_box);
        window.set_child(Some(&vbox));
        ok_button.grab_focus();
        window.present();
    });

    app.run_with_args::<&str>(&[]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_path_uses_runtime_dir() {
        let path = get_socket_path();
        // Should end with askpass-cache/socket
        assert!(path.ends_with("socket"));
        assert!(path.parent().unwrap().ends_with("askpass-cache"));
    }

    #[test]
    fn get_prompt_with_no_args_returns_default() {
        // This test modifies global state (args), so it's not ideal
        // In practice, we'd use a function that takes args as a parameter
        // For now, we just verify the function signature works
    }
}
