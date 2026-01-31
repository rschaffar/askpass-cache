# secure-askpass

A secure, generic credential caching daemon for Linux with proper memory protection.

## Problem Statement

When using SSH with FIDO2 hardware keys (like Yubikey), users are prompted for their PIN on every operation. While `gpg-agent` provides excellent secure caching for GPG passphrases, no equivalent exists for generic askpass scenarios (SSH_ASKPASS, GIT_ASKPASS, SUDO_ASKPASS).

### Current Workarounds and Their Limitations

| Solution | Problem |
|----------|---------|
| **No caching** | Annoying - enter PIN for every git push, SSH connection |
| **GNOME Keyring** | No askpass binary; secrets accessible to any app via D-Bus |
| **KDE Wallet + ksshaskpass** | Works but pulls in Qt/KDE dependencies on GNOME |
| **Custom Python script** | No secure memory (no zeroing, no mlock, GC-managed) |
| **gpg-agent GET_PASSPHRASE** | Hacky, not designed for this use case |

### Security Requirements (What GPG-Agent Does Right)

GPG-agent's credential handling (from `gnupg/agent/cache.c`):
1. **Secure memory allocation** - `gcry_malloc_secure()` uses mlock to prevent swapping
2. **Automatic zeroing** - Memory is explicitly zeroed before free
3. **No secret copies** - Careful to avoid unnecessary string copies
4. **AES encryption** - Cached passphrases are encrypted in memory
5. **TTL-based expiry** - Automatic cache clearing after timeout
6. **Event-based clearing** - Cache cleared on card removal, lock screen, etc.

## Solution: secure-askpass

A minimal, focused Rust daemon that provides secure credential caching for any askpass use case.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     User Session                                 │
│                                                                  │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐                     │
│  │   SSH    │   │   Git    │   │  sudo    │                     │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘                     │
│       │              │              │                            │
│       ▼              ▼              ▼                            │
│  SSH_ASKPASS    GIT_ASKPASS   SUDO_ASKPASS                      │
│       │              │              │                            │
│       └──────────────┼──────────────┘                           │
│                      ▼                                           │
│            ┌─────────────────┐                                   │
│            │  askpass-client │  (thin binary, ~50 lines)        │
│            │                 │                                   │
│            │  - Connects to socket                              │
│            │  - Sends prompt text                               │
│            │  - Receives credential                             │
│            │  - Prints to stdout                                │
│            │  - Zeros memory before exit                        │
│            └────────┬────────┘                                   │
│                     │ Unix Socket                                │
│                     ▼                                            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              secure-askpass-daemon                        │   │
│  │                                                           │   │
│  │  ┌─────────────────────────────────────────────────────┐ │   │
│  │  │              Secure Memory Region                    │ │   │
│  │  │              (mlock, no swap)                        │ │   │
│  │  │                                                      │ │   │
│  │  │  ┌────────────────────────────────────────────────┐ │ │   │
│  │  │  │           Credential Cache                     │ │ │   │
│  │  │  │                                                │ │ │   │
│  │  │  │  cache_id -> SecretString (auto-zeroize)      │ │ │   │
│  │  │  │  - TTL per entry                              │ │ │   │
│  │  │  │  - Optional AES encryption                    │ │ │   │
│  │  │  └────────────────────────────────────────────────┘ │ │   │
│  │  └─────────────────────────────────────────────────────┘ │   │
│  │                                                           │   │
│  │  ┌─────────────────┐    ┌─────────────────────────────┐  │   │
│  │  │  Socket Server  │    │  GTK4/libadwaita Prompter   │  │   │
│  │  │                 │    │                             │  │   │
│  │  │  - Accept conn  │    │  - Native Wayland/X11      │  │   │
│  │  │  - Parse request│    │  - Password entry widget   │  │   │
│  │  │  - Check cache  │    │  - "Remember" checkbox     │  │   │
│  │  │  - Return cred  │    │  - Timeout auto-cancel     │  │   │
│  │  └─────────────────┘    └─────────────────────────────┘  │   │
│  │                                                           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  systemd user service: secure-askpass.socket (socket activation) │
└─────────────────────────────────────────────────────────────────┘
```

### Modular Architecture

The daemon is designed with clear separation between secure core logic and UI presentation:

```
secure-askpass-daemon/
├── Core (Security-Critical)
│   ├── cache/          # Secure credential storage (mlock, zeroize)
│   ├── protocol/       # Unix socket IPC handling
│   └── auth/           # Authentication logic
│
├── UI Layer (Decoupled)
│   ├── prompt/
│   │   ├── trait.rs       # PasswordPrompt trait (abstraction)
│   │   ├── libadwaita.rs  # libadwaita implementation (default)
│   │   └── gtk4.rs        # Pure GTK4 implementation (future)
│   └── ...
│
├── Platform Integration (Pluggable)
│   ├── socket/
│   │   ├── trait.rs       # SocketProvider trait
│   │   ├── systemd.rs     # systemd socket activation
│   │   └── manual.rs      # Manual socket binding (testing)
│   └── events/
│       ├── trait.rs       # EventMonitor trait
│       ├── dbus.rs        # D-Bus event monitoring (lock screen, suspend)
│       └── mock.rs        # Mock events for testing
│
└── Daemon Orchestration
    └── main.rs         # Coordinates core + UI + platform
```

**Key Principles:**

1. **Secure Core is UI-Agnostic**
   - Cache, protocol, and auth modules have ZERO UI dependencies
   - Can be tested without GTK/display
   - Security audit can focus on core modules (~500 LOC)

2. **UI Layer Behind Trait**
   ```rust
   pub trait PasswordPrompt: Send + Sync {
       async fn prompt(&self, config: PromptConfig) -> Result<PromptResponse>;
   }
   ```
   - Daemon depends on trait, not concrete implementation
   - Easy to swap implementations (libadwaita → gtk4 → zenity fallback)
   - Mockable for testing

3. **Platform Integration Behind Traits**
   ```rust
   pub trait SocketProvider: Send + Sync {
       async fn listen(&self) -> Result<UnixListener>;
   }
   
   pub trait EventMonitor: Send + Sync {
       async fn next_event(&mut self) -> Option<SystemEvent>;
   }
   ```
   - Socket activation can be systemd or manual
   - Event monitoring can be D-Bus, mock, or disabled
   - Enables testing without systemd

4. **Compile-Time UI Selection**
   ```toml
   [features]
   default = ["ui-libadwaita"]
   ui-libadwaita = ["dep:libadwaita"]
   ui-gtk4 = []           # Future: Pure GTK4
   ui-cli = []            # Fallback for headless (rpassword)
   ```

5. **Clean Boundaries**
   - Core never imports `gtk4` or `libadwaita`
   - UI never imports `cache` internals
   - Protocol types are in shared `types` module
   - Each module is independently testable

**Testability by Design:**

All components are structured to enable comprehensive testing:

- **Unit Tests**: Core modules (cache, protocol, auth) with zero external dependencies
- **Integration Tests**: Mock UI + real core to test business logic
- **Component Tests**: Individual modules with trait implementations mocked
- **E2E Tests**: Full daemon with real GTK in Xvfb (CI environment)
- **Security Tests**: Memory leak detection, buffer overflow tests, fuzzing protocol

### Components

#### 1. `secure-askpass-daemon`

The main daemon process, started via systemd socket activation.

**Responsibilities:**
- Listen on Unix socket (`$XDG_RUNTIME_DIR/secure-askpass/socket`)
- Maintain credential cache in secure memory
- Show password prompts when cache miss (via PasswordPrompt trait)
- Handle TTL expiry and manual cache clearing
- Monitor system events for cache clearing triggers

**Secure Memory Handling (Rust):**
```rust
// In cache/ module - NO UI dependencies
use secrecy::{Secret, ExposeSecret, Zeroize};
use memsec::mlock;

struct CachedCredential {
    secret: Secret<String>,      // Auto-zeros on drop
    created_at: Instant,
    ttl: Duration,
}

// Lock the credential cache memory region
unsafe { mlock(cache_ptr, cache_size); }
```

**Note:** The cache module is completely decoupled from UI code, allowing:
- Security audits without reviewing GTK code
- Unit tests without display server
- Future headless/CLI-only builds

**Cache Key Strategy:**
- For SSH FIDO2: Hash of `"ssh-fido:" + key_fingerprint`
- For Git: `"git:" + protocol + "://" + host`
- For sudo: `"sudo:" + username`
- Generic: `"custom:" + user-provided-id`

**UI Implementation (Default: libadwaita):**
```rust
use gtk4::{PasswordEntry, PasswordEntryBuffer};
use libadwaita::AlertDialog;

// GTK4's PasswordEntryBuffer provides secure memory handling
let buffer = PasswordEntryBuffer::new(None);
let password_entry = PasswordEntry::builder()
    .buffer(&buffer)
    .show_peek_icon(true)
    .build();

// Wrap in libadwaita AlertDialog for modern GNOME look
let dialog = AlertDialog::builder()
    .heading("Authentication Required")
    .body(&prompt_text)
    .extra_child(&password_entry)
    .build();
```

#### 2. `askpass-client`

Minimal binary that serves as SSH_ASKPASS, GIT_ASKPASS, SUDO_ASKPASS.

**Behavior:**
1. Connect to daemon socket
2. Send request: `{"prompt": "Enter PIN for key ...", "cache_id": "auto"}`
3. Receive response: `{"credential": "...", "from_cache": true}`
4. Print credential to stdout
5. Zero all memory, exit

**Auto cache_id detection:**
- Parses prompt text to determine type (SSH key fingerprint, Git URL, etc.)
- Falls back to hash of full prompt if unrecognized

#### 3. `askpass-cache-clear`

Utility to manually clear the cache.

```bash
# Clear all cached credentials
askpass-cache-clear --all

# Clear specific cache entry
askpass-cache-clear --id "ssh-fido:SHA256:abc123..."

# Clear by type
askpass-cache-clear --type ssh
askpass-cache-clear --type git
```

### Testing Strategy

The modular architecture enables comprehensive testing at multiple levels:

#### Unit Tests (No External Dependencies)

Test core modules in complete isolation:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn cache_stores_and_retrieves_credential() {
        let mut cache = CredentialCache::new();
        let secret = Secret::new("test-password".to_string());
        cache.insert("test-key", secret, Duration::from_secs(60));
        
        let retrieved = cache.get("test-key").unwrap();
        assert_eq!(retrieved.expose_secret(), "test-password");
    }
    
    #[test]
    fn cache_expires_after_ttl() {
        // Test TTL expiry logic without any I/O
    }
    
    #[test]
    fn protocol_parses_valid_request() {
        let json = r#"{"type":"get_credential","prompt":"test"}"#;
        let request = parse_request(json).unwrap();
        assert_eq!(request.prompt, "test");
    }
}
```

**Target:** >80% coverage of `cache/`, `protocol/`, `auth/` modules

#### Integration Tests (Mock Implementations)

Test business logic with mocked dependencies:

```rust
#[tokio::test]
async fn daemon_prompts_on_cache_miss() {
    let mut mock_prompt = MockPasswordPrompt::new();
    mock_prompt.expect_prompt()
        .returning(|_| Ok(PromptResponse { 
            credential: Secret::new("password".into()),
            should_cache: true 
        }));
    
    let daemon = Daemon::new(
        mock_prompt,
        MockSocketProvider::new(),
        MockEventMonitor::new(),
    );
    
    let response = daemon.handle_request(/* ... */).await.unwrap();
    assert_eq!(response.from_cache, false);
}

#[tokio::test]
async fn daemon_returns_from_cache_on_hit() {
    // Pre-populate cache, verify no prompt is shown
}

#[tokio::test]
async fn daemon_clears_cache_on_lock_event() {
    // Trigger lock event, verify cache is cleared
}
```

**Tools:** `mockall` crate for trait mocking

#### Component Tests (Real Module + Mock Dependencies)

Test individual modules with real implementation:

```rust
#[test]
fn socket_provider_systemd_parses_fd() {
    std::env::set_var("LISTEN_FDS", "1");
    let provider = SystemdSocketProvider::new();
    // Test actual systemd socket activation parsing
}

#[test]
fn event_monitor_dbus_receives_lock_signal() {
    // Test real D-Bus integration (requires dbus-daemon in test env)
}
```

#### End-to-End Tests (Full Stack in CI)

Test complete daemon with real GTK in headless environment:

```bash
# In CI (GitHub Actions, etc.)
export DISPLAY=:99
Xvfb :99 -screen 0 1024x768x24 &

# Run E2E tests
cargo test --test e2e_tests --features ui-libadwaita

# Test scenarios:
# - Client connects, daemon shows prompt, returns credential
# - Cached credential is returned without prompt
# - Cache clears after TTL expires
# - Daemon survives client disconnection
```

**Tools:** Xvfb for headless GTK testing

#### Security Tests

Verify security properties:

```rust
#[test]
fn credential_is_zeroized_on_drop() {
    use std::ptr;
    let secret = Secret::new("password".to_string());
    let ptr = secret.expose_secret().as_ptr();
    drop(secret);
    
    // Verify memory is zeroed (requires unsafe inspection)
    // This is a conceptual test - actual implementation may vary
}

#[test]
fn cache_memory_is_mlocked() {
    // Verify mlock was called on cache region
}
```

**Additional Security Testing:**
- **Fuzzing**: Use `cargo-fuzz` to fuzz protocol parser
- **Memory leak detection**: Run with valgrind/ASAN
- **Miri**: Test unsafe code with `cargo miri test`
- **cargo-audit**: Automated vulnerability scanning in CI

#### Property-Based Tests

Use `proptest` for protocol robustness:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn protocol_never_panics_on_invalid_json(s in "\\PC*") {
        // Verify parser returns error instead of panicking
        let _ = parse_request(&s);
    }
    
    #[test]
    fn cache_id_hash_is_deterministic(input in ".*") {
        let hash1 = compute_cache_id(&input);
        let hash2 = compute_cache_id(&input);
        assert_eq!(hash1, hash2);
    }
}
```

#### Test Organization

```
tests/
├── unit/              # Module-level unit tests (in src/)
├── integration/       # Integration tests with mocks
│   ├── cache_tests.rs
│   ├── daemon_tests.rs
│   └── protocol_tests.rs
├── component/         # Individual component tests
│   ├── socket_tests.rs
│   └── events_tests.rs
├── e2e/               # Full stack tests
│   └── daemon_e2e.rs
├── security/          # Security-specific tests
│   ├── memory_tests.rs
│   └── fuzzing/
└── common/            # Shared test utilities
    └── mod.rs
```

**CI Pipeline:**

```yaml
# .github/workflows/test.yml
- Unit tests: Fast, run on every commit
- Integration tests: Run on every PR
- E2E tests: Run on every PR (with Xvfb)
- Security tests: Run nightly
- Fuzzing: Continuous (separate workflow)
```

### Protocol

Simple JSON over Unix socket (newline-delimited):

**Request (client -> daemon):**
```json
{
  "type": "get_credential",
  "prompt": "Enter PIN for ECDSA-SK key /home/user/.ssh/id_ecdsa_sk:",
  "cache_id": "auto",
  "allow_cache": true,
  "echo": false
}
```

**Response (daemon -> client):**
```json
{
  "type": "credential",
  "value": "123456",
  "from_cache": false
}
```

**Error response:**
```json
{
  "type": "error",
  "code": "cancelled",
  "message": "User cancelled the prompt"
}
```

**Cache clear request:**
```json
{
  "type": "clear_cache",
  "cache_id": "all"
}
```

### GTK4 Prompt Dialog

Native libadwaita dialog for GNOME integration:

```
┌─────────────────────────────────────────────┐
│  Authentication Required                     │
├─────────────────────────────────────────────┤
│                                             │
│  Enter PIN for ECDSA-SK key:                │
│  SHA256:xK3N...                             │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │ ●●●●●●                           👁 │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  ☑ Remember for this session                │
│                                             │
│  Timeout: 28s                               │
│                                             │
│         [ Cancel ]        [ Authenticate ]  │
└─────────────────────────────────────────────┘
```

**Features:**
- Password visibility toggle
- "Remember for session" checkbox (controls caching)
- Auto-cancel timeout (default 30s)
- Proper Wayland layer-shell hints for security
- Keyboard grab to prevent other apps capturing input

### Configuration

`~/.config/secure-askpass/config.toml`:

```toml
[cache]
# Default TTL for cached credentials (seconds)
default_ttl = 3600

# Maximum TTL (even if user requests longer)
max_ttl = 86400

# Clear cache on screen lock
clear_on_lock = true

# Clear cache on suspend
clear_on_suspend = true

[prompt]
# Timeout for user response (seconds)
timeout = 30

# Default state of "remember" checkbox
default_remember = true

[security]
# Encrypt cached credentials with session key
encrypt_cache = true

# Require user confirmation even for cached credentials
# (shows brief "Using cached credential" notification)
confirm_cached = false
```

### systemd Integration

**`secure-askpass.socket`:**
```ini
[Unit]
Description=Secure Askpass Daemon Socket

[Socket]
ListenStream=%t/secure-askpass/socket
SocketMode=0600

[Install]
WantedBy=sockets.target
```

**`secure-askpass.service`:**
```ini
[Unit]
Description=Secure Askpass Daemon
Requires=secure-askpass.socket

[Service]
Type=notify
ExecStart=/usr/bin/secure-askpass-daemon
MemoryDenyWriteExecute=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
```

### NixOS Integration

```nix
# In home-manager module
{ config, pkgs, ... }:
{
  services.secure-askpass = {
    enable = true;
    settings = {
      cache.default_ttl = 3600;
      cache.clear_on_lock = true;
    };
  };

  # Automatically set environment variables
  home.sessionVariables = {
    SSH_ASKPASS = "${pkgs.secure-askpass}/bin/askpass-client";
    SSH_ASKPASS_REQUIRE = "prefer";
    GIT_ASKPASS = "${pkgs.secure-askpass}/bin/askpass-client";
    SUDO_ASKPASS = "${pkgs.secure-askpass}/bin/askpass-client";
  };
}
```

### Security Considerations

#### Memory Protection
- All secrets stored in `Secret<T>` wrapper (auto-zeroize on drop)
- Cache memory region locked with `mlock()` to prevent swapping
- Rust ownership model prevents accidental secret copies
- No secret logging (secrecy crate prevents `Debug`/`Display` impl)

#### IPC Security
- Unix socket with mode 0600 (owner-only)
- Socket in `$XDG_RUNTIME_DIR` (tmpfs, user-only)
- No D-Bus exposure (avoids GNOME Keyring's any-app-can-read problem)

#### Prompt Security
- GTK4 password entry widget (better than zenity command-line)
- Wayland: Use layer-shell for proper security context
- X11: Grab keyboard during prompt (prevent keyloggers)
- Timeout to prevent indefinite credential exposure

#### Optional: Encrypted Cache
Like GPG-agent, optionally encrypt cached credentials:
- Generate random session key at daemon start
- AES-256-GCM encrypt credentials in cache
- Key held only in locked memory
- Provides defense-in-depth against memory dumps

### Crates to Use

```toml
[dependencies]
# Secure memory
secrecy = { version = "0.10", features = ["serde"] }  # Secret<T> wrapper with zeroize
zeroize = { version = "1.8", features = ["derive"] }  # Explicit memory zeroing
memsec = "0.6"                                        # mlock/mprotect bindings

# Async runtime
tokio = { version = "1", features = ["full"] }

# IPC
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# GUI (default: libadwaita)
gtk4 = { version = "0.10", features = ["v4_4"] }
libadwaita = { version = "0.8", features = ["v1_2"], optional = true }

# Config
toml = "0.8"
dirs = "5"                # XDG directories

# Platform integration
zbus = "4"                # D-Bus integration for event monitoring
sd-notify = "0.4"         # systemd notification

# Crypto (optional, for encrypted cache)
aes-gcm = "0.10"
rand = "0.8"

# CLI fallback (optional)
rpassword = { version = "7.4", optional = true }

# Logging
tracing = "0.1"
tracing-subscriber = "0.3"

# Testing
[dev-dependencies]
mockall = "0.13"          # Mock trait implementations
proptest = "1"            # Property-based testing
tempfile = "3"            # Temporary directories for tests

[features]
default = ["ui-libadwaita"]
ui-libadwaita = ["dep:libadwaita"]
ui-gtk4 = []              # Pure GTK4 (future)
ui-cli = ["dep:rpassword"]  # CLI fallback
```

### Implementation Phases

#### Phase 1: Core Daemon (MVP)
- [ ] Define core traits (`PasswordPrompt`, `SocketProvider`, `EventMonitor`)
- [ ] Implement secure cache module (mlock, `Secret<String>`, TTL)
- [ ] Implement protocol module (JSON over Unix socket)
- [ ] Basic daemon orchestration with trait-based dependencies
- [ ] Simple zenity-based prompt implementation (temporary, for testing)
- [ ] `askpass-client` binary with secure memory handling
- [ ] Unit tests for cache and protocol modules
- [ ] Works as SSH_ASKPASS

#### Phase 2: Proper GUI
- [ ] GTK4/libadwaita password dialog implementing `PasswordPrompt` trait
- [ ] "Remember for session" checkbox
- [ ] Proper keyboard handling (grab on X11, layer-shell on Wayland)
- [ ] Timeout with visual countdown
- [ ] Password visibility toggle
- [ ] Component tests for UI module (with mock core)
- [ ] E2E tests with Xvfb in CI

#### Phase 3: Security Hardening
- [ ] mlock for cache memory region
- [ ] Optional AES-256-GCM encryption of cached credentials
- [ ] D-Bus event monitoring implementation (`EventMonitor` trait)
- [ ] Clear-on-lock integration (listen for screensaver signals)
- [ ] Clear-on-suspend integration
- [ ] systemd hardening options (MemoryDenyWriteExecute, etc.)
- [ ] Security tests (memory leak detection, fuzzing protocol)
- [ ] Third-party security audit of core modules

#### Phase 4: Testing & CI
- [ ] Comprehensive unit test suite (>80% coverage of core)
- [ ] Integration tests with mock implementations
- [ ] Property-based tests for protocol parsing (proptest)
- [ ] Memory safety tests (valgrind, miri)
- [ ] CI pipeline (GitHub Actions or similar)
- [ ] Automated security scanning (cargo-audit, cargo-deny)
- [ ] Performance benchmarks for cache operations

#### Phase 5: NixOS Integration
- [ ] Nix package derivation
- [ ] Home-manager module with configuration options
- [ ] Integration with existing `modules/security.nix`
- [ ] NixOS VM tests for E2E validation
- [ ] Documentation for NixOS users

#### Phase 6: Polish & Extensibility
- [ ] Configuration file support with validation
- [ ] `askpass-cache-clear` utility
- [ ] Pure GTK4 UI implementation (feature flag: `ui-gtk4`)
- [ ] CLI-only fallback (feature flag: `ui-cli`, using rpassword)
- [ ] Comprehensive user documentation
- [ ] API documentation for trait implementations
- [ ] Consider extracting UI prompt to separate crate (`libadwaita-secure-prompt`)

### Prior Art & References

- **GPG-agent cache.c**: Reference implementation for secure caching
  - Source: `gnupg/agent/cache.c` 
  - Key patterns: AES encryption, TTL, event-based clearing

- **xaskpass**: Rust askpass with secure memory, but X11-only, no daemon
  - https://github.com/xask/xaskpass
  - Uses `secstr` crate for secure strings

- **ksshaskpass**: KDE's SSH askpass with KWallet integration
  - Works but requires Qt/KDE dependencies

- **git-credential-cache**: Simple daemon pattern
  - Reference for Unix socket + timeout architecture

### Open Questions

1. **Should cached credentials require re-authentication after screen unlock?**
   - GPG-agent can be configured this way
   - Trade-off between security and convenience

2. **Multi-seat support?**
   - Current design assumes single-user session
   - Probably not needed for desktop use case

3. **Integration with existing keyrings?**
   - Could optionally store in GNOME Keyring for persistence across reboots
   - But that defeats the "session-only" security model

4. **FIDO2 touch-only prompts?**
   - SSH sometimes asks for "touch only" (no PIN)
   - Current detection: if prompt doesn't mention "PIN", return empty immediately
   - Need to verify this heuristic is robust

---

## Getting Started

```bash
# Clone and build
cd ~/projects/priv/secure-askpass
cargo build --release

# Run daemon (for development)
cargo run --bin secure-askpass-daemon

# Test with SSH
SSH_ASKPASS=./target/release/askpass-client \
SSH_ASKPASS_REQUIRE=force \
ssh-add -K ~/.ssh/id_ecdsa_sk
```

## License

MIT OR Apache-2.0 (standard Rust dual-license)
