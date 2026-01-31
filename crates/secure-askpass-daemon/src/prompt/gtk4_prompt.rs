//! GTK4 password prompt implementation.
//!
//! This module provides a GTK4-based password dialog that implements
//! the [`PasswordPrompt`] trait. It creates a simple dialog with:
//!
//! - A password entry field with visibility toggle
//! - A "Remember for session" checkbox
//! - Cancel and Authenticate buttons
//! - Timeout handling

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;

use gtk4::glib;
use gtk4::prelude::*;
use secrecy::SecretString;
use secure_askpass_core::{PasswordPrompt, PromptConfig, PromptError, PromptResponse};
use tokio::sync::oneshot;
use tracing::{debug, warn};

/// GTK4-based password prompt.
///
/// This implementation creates a GTK4 dialog window for password entry.
/// It handles the complexity of bridging GTK4's main loop with Tokio's
/// async runtime.
pub struct Gtk4PasswordPrompt {
    /// Application ID for GTK.
    #[allow(dead_code)] // Will be used for proper GTK application in future
    app_id: String,
}

impl Gtk4PasswordPrompt {
    /// Create a new GTK4 password prompt.
    pub fn new() -> Self {
        Self {
            app_id: "com.secure-askpass.prompt".to_string(),
        }
    }

    /// Create with a custom application ID.
    pub fn with_app_id(app_id: impl Into<String>) -> Self {
        Self {
            app_id: app_id.into(),
        }
    }

    /// Show the password dialog and wait for user input.
    ///
    /// This function must be called from within a GTK main context.
    fn show_dialog(config: PromptConfig) -> oneshot::Receiver<Result<PromptResponse, PromptError>> {
        let (tx, rx) = oneshot::channel();
        let tx = Rc::new(RefCell::new(Some(tx)));

        // Create the dialog window
        let window = gtk4::Window::builder()
            .title("Authentication Required")
            .default_width(400)
            .default_height(200)
            .modal(true)
            .resizable(false)
            .build();

        // Main vertical box
        let vbox = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(12)
            .margin_top(20)
            .margin_bottom(20)
            .margin_start(20)
            .margin_end(20)
            .build();

        // Prompt label
        let prompt_label = gtk4::Label::builder()
            .label(&config.prompt_text)
            .wrap(true)
            .xalign(0.0)
            .build();
        vbox.append(&prompt_label);

        // Password entry
        let password_entry = gtk4::PasswordEntry::builder()
            .show_peek_icon(true)
            .placeholder_text("Enter password")
            .build();
        vbox.append(&password_entry);

        // Remember checkbox (if enabled)
        let remember_check = if config.show_remember_checkbox {
            let check = gtk4::CheckButton::builder()
                .label("Remember for this session")
                .active(true)
                .build();
            vbox.append(&check);
            Some(check)
        } else {
            None
        };

        // Timeout label
        let timeout_secs = config.timeout.as_secs();
        let timeout_label = gtk4::Label::builder()
            .label(format!("Timeout: {}s", timeout_secs))
            .xalign(0.0)
            .css_classes(["dim-label"])
            .build();
        vbox.append(&timeout_label);

        // Button box
        let button_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(12)
            .halign(gtk4::Align::End)
            .margin_top(12)
            .build();

        let cancel_button = gtk4::Button::builder().label("Cancel").build();

        let auth_button = gtk4::Button::builder()
            .label("Authenticate")
            .css_classes(["suggested-action"])
            .build();

        button_box.append(&cancel_button);
        button_box.append(&auth_button);
        vbox.append(&button_box);

        window.set_child(Some(&vbox));

        // Set up timeout
        let timeout_label_clone = timeout_label.clone();
        let window_clone = window.clone();
        let tx_timeout = Rc::clone(&tx);
        let remaining = Rc::new(RefCell::new(timeout_secs));

        glib::timeout_add_local(Duration::from_secs(1), move || {
            let mut secs = remaining.borrow_mut();
            if *secs > 0 {
                *secs -= 1;
                timeout_label_clone.set_label(&format!("Timeout: {}s", *secs));
                glib::ControlFlow::Continue
            } else {
                // Timeout reached
                if let Some(tx) = tx_timeout.borrow_mut().take() {
                    let _ = tx.send(Err(PromptError::Timeout(timeout_secs)));
                }
                window_clone.close();
                glib::ControlFlow::Break
            }
        });

        // Handle cancel button
        let window_cancel = window.clone();
        let tx_cancel = Rc::clone(&tx);
        cancel_button.connect_clicked(move |_| {
            if let Some(tx) = tx_cancel.borrow_mut().take() {
                let _ = tx.send(Err(PromptError::Cancelled));
            }
            window_cancel.close();
        });

        // Handle authenticate button
        let window_auth = window.clone();
        let password_entry_auth = password_entry.clone();
        let remember_check_auth = remember_check.clone();
        let tx_auth = Rc::clone(&tx);
        auth_button.connect_clicked(move |_| {
            let password = password_entry_auth.text().to_string();
            let should_cache = remember_check_auth
                .as_ref()
                .map(|c| c.is_active())
                .unwrap_or(false);

            if let Some(tx) = tx_auth.borrow_mut().take() {
                let _ = tx.send(Ok(PromptResponse {
                    credential: SecretString::from(password),
                    should_cache,
                }));
            }
            window_auth.close();
        });

        // Handle Enter key in password entry
        let auth_button_enter = auth_button.clone();
        password_entry.connect_activate(move |_| {
            auth_button_enter.emit_clicked();
        });

        // Handle window close
        let tx_close = Rc::clone(&tx);
        window.connect_close_request(move |_| {
            if let Some(tx) = tx_close.borrow_mut().take() {
                let _ = tx.send(Err(PromptError::Cancelled));
            }
            glib::Propagation::Proceed
        });

        // Show the window
        window.present();

        // Focus the password entry
        password_entry.grab_focus();

        rx
    }
}

impl Default for Gtk4PasswordPrompt {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordPrompt for Gtk4PasswordPrompt {
    fn prompt(
        &self,
        config: PromptConfig,
    ) -> Pin<Box<dyn Future<Output = Result<PromptResponse, PromptError>> + Send + '_>> {
        Box::pin(async move {
            // We need to run GTK on the main thread.
            // Use a channel to communicate between the GTK thread and the async task.
            let (_result_tx, _result_rx) =
                oneshot::channel::<Result<PromptResponse, PromptError>>();

            // Spawn a blocking task to run GTK
            let handle = tokio::task::spawn_blocking(move || {
                // Initialize GTK if not already done
                if gtk4::is_initialized() {
                    debug!("GTK already initialized, reusing");
                } else {
                    debug!("Initializing GTK");
                    gtk4::init().map_err(|e| {
                        PromptError::InitializationFailed(format!("GTK init failed: {}", e))
                    })?;
                }

                // Create a main context for this thread
                let main_context = glib::MainContext::default();
                let _guard = main_context.acquire().map_err(|_| {
                    PromptError::InitializationFailed("Failed to acquire main context".into())
                })?;

                // Show the dialog and get the receiver
                let mut dialog_rx = Self::show_dialog(config);

                // Run the main loop until we get a result
                let result = main_context.block_on(async {
                    // Poll GTK events while waiting for the dialog result
                    loop {
                        // Process pending GTK events
                        while main_context.iteration(false) {}

                        // Check if we have a result
                        match dialog_rx.try_recv() {
                            Ok(result) => break result,
                            Err(oneshot::error::TryRecvError::Empty) => {
                                // No result yet, yield and continue
                                tokio::task::yield_now().await;
                            }
                            Err(oneshot::error::TryRecvError::Closed) => {
                                // Channel closed without result
                                break Err(PromptError::Cancelled);
                            }
                        }
                    }
                });

                Ok::<_, PromptError>(result)
            });

            // Wait for the blocking task to complete
            match handle.await {
                Ok(Ok(result)) => result,
                Ok(Err(e)) => Err(e),
                Err(e) => {
                    warn!(error = %e, "GTK task panicked");
                    Err(PromptError::UiError(format!("GTK task failed: {}", e)))
                }
            }
        })
    }
}

// Note: GTK4 tests require a display server or Xvfb.
// These tests are marked as ignored by default and should be run with:
// xvfb-run cargo test -p secure-askpass-daemon
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_prompt() {
        let _prompt = Gtk4PasswordPrompt::new();
    }

    #[test]
    fn can_create_with_app_id() {
        let prompt = Gtk4PasswordPrompt::with_app_id("test.app.id");
        assert_eq!(prompt.app_id, "test.app.id");
    }

    // Integration tests requiring display server
    // Run with: xvfb-run cargo test -p secure-askpass-daemon -- --ignored

    #[tokio::test]
    #[ignore = "requires display server"]
    async fn prompt_shows_dialog() {
        let prompt = Gtk4PasswordPrompt::new();
        let config = PromptConfig {
            prompt_text: "Test prompt".to_string(),
            timeout: Duration::from_secs(5),
            ..Default::default()
        };

        // This will show a dialog - manually close it or wait for timeout
        let _ = prompt.prompt(config).await;
    }
}
