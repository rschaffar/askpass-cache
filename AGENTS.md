# AGENTS.md - Guidelines for AI Coding Agents

This document provides essential information for AI agents working on the secure-askpass codebase.

## Project Overview

Secure-askpass is a Rust daemon providing secure credential caching for SSH_ASKPASS, GIT_ASKPASS, and SUDO_ASKPASS with proper memory protection (mlock, auto-zeroing). It's a Cargo workspace with four crates.

**Status:** Phase 1 implementation in progress (infrastructure complete).

## Repository Structure

```
crates/
  secure-askpass-core/     # Core types, secure memory utilities
  secure-askpass-daemon/   # Main daemon process
  askpass-client/          # Thin binary for SSH_ASKPASS/GIT_ASKPASS/SUDO_ASKPASS
  askpass-cache-clear/     # Utility to manually clear cache
nix/
  package.nix              # Nix build definition
  devshell.nix             # Development environment
  modules/                 # NixOS and home-manager modules
```

## Build Commands

```bash
# Standard build (all crates)
cargo build
cargo build --release

# Build specific crate
cargo build -p secure-askpass-daemon
cargo build -p askpass-client

# Using Nix
nix build                  # Build release package
nix develop                # Enter dev shell with all dependencies
```

## Testing Commands

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p secure-askpass-core
cargo test -p secure-askpass-daemon

# Run a single test by name
cargo test test_name
cargo test -p secure-askpass-core test_name

# Run tests with output
cargo test -- --nocapture

# Run GTK tests (requires display server or Xvfb)
xvfb-run cargo test

# Run tests with specific features
cargo test --features ui-libadwaita
```

## Linting and Formatting

```bash
# Format code
cargo fmt
cargo fmt --check           # CI check (fails if not formatted)

# Run clippy lints
cargo clippy
cargo clippy --all-targets --all-features -- -D warnings

# Security audit
cargo audit

# Continuous checking during development
cargo watch -x check        # Auto-check on file changes
bacon                       # Background code checker
```

## Nix Commands

```bash
nix develop                 # Enter development shell
nix build                   # Build the package
nix fmt                     # Format Nix files
nix flake check             # Validate flake
```

## Code Style Guidelines

### Rust Edition and Toolchain

- **Edition:** Rust 2021
- **Toolchain:** Stable (defined in rust-toolchain.toml)
- **Components:** rustfmt, clippy, rust-analyzer

### Import Organization

Order imports in this sequence, separated by blank lines:

```rust
// 1. Standard library
use std::collections::HashMap;
use std::sync::Arc;

// 2. External crates (alphabetical)
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

// 3. Workspace crates
use secure_askpass_core::types::CacheType;

// 4. Current crate modules
use crate::cache::CredentialCache;
use super::protocol;
```

### Naming Conventions

- **Types:** PascalCase (`CachedCredential`, `PromptConfig`)
- **Functions/methods:** snake_case (`get_credential`, `clear_cache`)
- **Constants:** SCREAMING_SNAKE_CASE (`DEFAULT_TTL`, `MAX_CACHE_SIZE`)
- **Modules:** snake_case (`secure_memory`, `event_monitor`)
- **Traits:** PascalCase, often adjectives (`PasswordPrompt`, `EventMonitor`)

### Type Annotations

- Prefer explicit types for public APIs
- Use type inference for local variables when type is obvious
- Always annotate closure parameters in complex scenarios

```rust
// Good: explicit public API
pub fn insert(&mut self, key: &str, secret: Secret<String>, ttl: Duration)

// Good: obvious local inference
let cache = CredentialCache::new();

// Good: annotated complex closure
entries.retain(|k, v| -> bool { !v.is_expired() });
```

### Error Handling

- Use `Result<T, E>` for fallible operations
- Prefer `anyhow::Result` for applications, `thiserror` for libraries
- Avoid `unwrap()` in production code; use `expect()` with descriptive message if panic is intentional
- Use `?` operator for error propagation

```rust
// Good: descriptive expect
let listener = UnixListener::bind(&socket_path)
    .expect("socket binding should succeed after directory creation");

// Good: proper error propagation
pub async fn get_credential(&self, key: &str) -> Result<Option<Secret<String>>> {
    let cache = self.cache.lock().await;
    Ok(cache.get(key).cloned())
}
```

### Documentation

- Add doc comments (`///`) to all public items
- Use `//!` for module-level documentation
- Include examples in doc comments for complex APIs

```rust
//! Core types and utilities for secure-askpass

/// A cached credential with automatic expiry.
///
/// # Security
///
/// The credential is stored in a `Secret<String>` which automatically
/// zeros memory on drop.
pub struct CachedCredential {
    secret: Secret<String>,
    created_at: Instant,
    ttl: Duration,
}
```

### Security-Critical Code Patterns

This is a security-sensitive project. Follow these patterns:

```rust
// Always use Secret<T> for sensitive data
use secrecy::{Secret, ExposeSecret, Zeroize};

// Never log secrets
tracing::debug!("Processing credential for key: {}", cache_id);  // OK
tracing::debug!("Credential value: {}", secret.expose_secret()); // NEVER

// Use mlock for secure memory regions
use memsec::mlock;
unsafe { mlock(cache_ptr, cache_size); }

// Ensure cleanup with Drop
impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}
```

### Async/Await Patterns

- Use `tokio` runtime for async operations
- Prefer `tokio::sync::Mutex` over `std::sync::Mutex` for async code
- Use `async fn` for async functions

```rust
use tokio::sync::Mutex;

pub struct Daemon {
    cache: Arc<Mutex<CredentialCache>>,
}

impl Daemon {
    pub async fn handle_request(&self, req: Request) -> Result<Response> {
        let mut cache = self.cache.lock().await;
        // ...
    }
}
```

### Trait-Based Architecture

The daemon uses trait abstraction for testability:

```rust
// Define trait for abstraction
pub trait PasswordPrompt: Send + Sync {
    async fn prompt(&self, config: PromptConfig) -> Result<PromptResponse>;
}

// Implement for production
pub struct LibadwaitaPrompt { /* ... */ }
impl PasswordPrompt for LibadwaitaPrompt { /* ... */ }

// Mock for testing
#[cfg(test)]
pub struct MockPrompt { /* ... */ }
```

### Testing Patterns

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_stores_and_retrieves_credential() {
        let mut cache = CredentialCache::new();
        // ...
    }

    #[tokio::test]
    async fn daemon_handles_request() {
        // Async test
    }
}
```

### Feature Flags

```toml
[features]
default = ["ui-libadwaita"]
ui-libadwaita = ["dep:libadwaita"]
ui-gtk4 = []
ui-cli = ["dep:rpassword"]
```

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| `secrecy` | Secret wrapper with auto-zeroize |
| `zeroize` | Explicit memory zeroing |
| `memsec` | mlock/mprotect bindings |
| `tokio` | Async runtime |
| `serde`/`serde_json` | Serialization |
| `gtk4`/`libadwaita` | GUI (optional) |
| `zbus` | D-Bus integration |
| `tracing` | Structured logging |
| `anyhow` | Error handling for binaries |
| `thiserror` | Custom error types for libraries |

## Architecture Notes

1. **Core is UI-agnostic:** `secure-askpass-core` has ZERO UI dependencies
2. **Traits for testability:** `PasswordPrompt`, `SocketProvider`, `EventMonitor`
3. **Security-first:** All secrets use `Secret<T>`, memory is mlocked
4. **Protocol:** JSON over Unix socket (newline-delimited)

## Common Pitfalls

- Never use `Debug` or `Display` on `Secret<T>` values
- Don't store secrets in plain `String` - always use `Secret<String>`
- Remember to run `cargo fmt` before committing
- GTK tests require a display server or `xvfb-run`
- Don't add unnecessary dependencies (security-critical codebase)

## References

- [CONCEPT.md](CONCEPT.md) - Detailed design document
- [README.md](README.md) - User documentation
