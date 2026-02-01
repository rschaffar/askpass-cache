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
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    askpass-client                          │  │
│  │  (inherits display environment from caller)                │  │
│  │                                                            │  │
│  │  1. Connect to daemon socket                               │  │
│  │  2. Send GetCredential request                             │  │
│  │  3. If CacheMiss:                                          │  │
│  │     ┌────────────────────────────────────────────────────┐ │  │
│  │     │         GTK4 Password Dialog                       │ │  │
│  │     │  - Native Wayland/X11 (inherits from caller)       │ │  │
│  │     │  - Password entry widget                           │ │  │
│  │     │  - "Remember for this session" checkbox            │ │  │
│  │     │  - Alt+R keyboard shortcut                         │ │  │
│  │     └────────────────────────────────────────────────────┘ │  │
│  │  4. Send StoreCredential (if remember checked)             │  │
│  │  5. Print credential to stdout                             │  │
│  │  6. Zero memory before exit                                │  │
│  └──────────────────────┬────────────────────────────────────┘  │
│                         │ Unix Socket                            │
│                         ▼                                        │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              secure-askpass-daemon                         │  │
│  │              (NO UI - cache only)                          │  │
│  │                                                            │  │
│  │  ┌──────────────────────────────────────────────────────┐ │  │
│  │  │              Secure Memory Region                     │ │  │
│  │  │              (mlock, no swap)                         │ │  │
│  │  │                                                       │ │  │
│  │  │  ┌─────────────────────────────────────────────────┐ │ │  │
│  │  │  │           Credential Cache                      │ │ │  │
│  │  │  │                                                 │ │ │  │
│  │  │  │  cache_id -> SecretString (auto-zeroize)       │ │ │  │
│  │  │  │  - TTL per entry                               │ │ │  │
│  │  │  │  - Optional AES encryption                     │ │ │  │
│  │  │  └─────────────────────────────────────────────────┘ │ │  │
│  │  └──────────────────────────────────────────────────────┘ │  │
│  │                                                            │  │
│  │  ┌──────────────────────────────────────────────────────┐ │  │
│  │  │  Socket Server                                       │ │  │
│  │  │  - Accept connections                                │ │  │
│  │  │  - Parse requests (GetCredential, StoreCredential)   │ │  │
│  │  │  - Return Credential (cache hit) or CacheMiss        │ │  │
│  │  │  - Handle ClearCache requests                        │ │  │
│  │  └──────────────────────────────────────────────────────┘ │  │
│  │                                                            │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  systemd user service: secure-askpass.socket (socket activation) │
└─────────────────────────────────────────────────────────────────┘
```

### Modular Architecture

The system is designed with clear separation: the daemon handles only secure caching, while the client handles all user interaction. This provides better security isolation and simpler testing.

```
secure-askpass-core/           # Shared library (NO UI dependencies)
├── cache.rs                   # Secure credential storage (mlock, zeroize)
├── cache_id.rs                # Auto-detection of cache IDs from prompts
├── protocol.rs                # Request/Response types for IPC
├── types.rs                   # CacheType enum with TTL defaults
└── traits.rs                  # SocketProvider, EventMonitor traits

secure-askpass-daemon/         # Cache daemon (NO UI dependencies)
├── daemon.rs                  # Request handling, cache management
├── socket/
│   ├── mod.rs                 # Default provider selection
│   ├── systemd.rs             # systemd socket activation
│   └── manual.rs              # Manual socket binding (dev/testing)
└── main.rs                    # Entry point, logging setup

askpass-client/                # UI client (has GTK4 dependency)
└── main.rs                    # GTK4 dialog, daemon communication

askpass-cache-ctl/             # CLI utility
└── main.rs                    # List/delete cached credentials
```

**Key Principles:**

1. **Daemon is UI-Free**
   - Daemon has ZERO GTK/UI dependencies
   - Can be tested without display server
   - Smaller attack surface for security-critical code
   - Security audit focuses on daemon + core (~1000 LOC)

2. **Client Handles All User Interaction**
   - Client inherits display environment from caller (SSH/Git/sudo)
   - This ensures dialogs appear in the correct graphical context
   - Client prompts user on cache miss, stores result in daemon
   - GTK4 dialog with "Remember for this session" checkbox

3. **Platform Integration Behind Traits**
   ```rust
   pub trait SocketProvider: Send + Sync {
       fn listen(&self) -> Pin<Box<dyn Future<Output = Result<UnixListener, SocketError>> + Send + '_>>;
   }
   
   pub trait EventMonitor: Send + Sync {
       fn next_event(&mut self) -> Pin<Box<dyn Future<Output = Option<SystemEvent>> + Send + '_>>;
   }
   ```
   - Socket activation can be systemd or manual
   - Event monitoring can be D-Bus, mock, or disabled
   - Enables testing without systemd

4. **Clean Boundaries**
   - `secure-askpass-core` never imports `gtk4`
   - `secure-askpass-daemon` never imports `gtk4`
   - Only `askpass-client` has UI dependencies
   - Protocol types are in shared core crate

**Testability by Design:**

All components are structured to enable comprehensive testing:

- **Unit Tests**: Core modules (cache, protocol, cache_id) with zero external dependencies
- **Daemon Tests**: Full request/response handling without display server
- **Client Tests**: GTK dialog tests require Xvfb (isolated from daemon tests)
- **Property Tests**: Protocol parsing and cache_id detection with proptest
- **Security Tests**: Memory leak detection, buffer overflow tests, fuzzing protocol

### Components

#### 1. `secure-askpass-daemon`

The main daemon process, started via systemd socket activation. **The daemon has NO UI dependencies** - it only manages the credential cache.

**Responsibilities:**
- Listen on Unix socket (`$XDG_RUNTIME_DIR/secure-askpass/socket`)
- Maintain credential cache in secure memory
- Handle `GetCredential` requests (return cached credential or `CacheMiss`)
- Handle `StoreCredential` requests (store credential from client)
- Handle `ClearCache` requests (manual or event-triggered clearing)
- Handle TTL expiry (background cleanup task)
- Monitor system events for cache clearing triggers (D-Bus)

**Secure Memory Handling (Rust):**
```rust
use secrecy::{Secret, ExposeSecret};
use memsec::mlock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheType {
    Ssh,    // 30 min TTL, clear on lock
    Git,    // 2 hour TTL, keep on lock
    Sudo,   // 5 min TTL, clear on lock
    Custom, // 1 hour TTL, clear on lock
}

pub struct CachedCredential {
    secret: SecretString,        // Auto-zeros on drop
    created_at: Instant,
    ttl: Duration,
    cache_type: CacheType,
}

// Lock the credential cache memory region
unsafe { mlock(cache_ptr, cache_size); }
```

**Note:** The daemon is completely decoupled from UI code, allowing:
- Security audits without reviewing GTK code
- Unit tests without display server
- Headless operation (client handles all UI)
- Per-type configuration for different security/convenience trade-offs

**Cache Key Strategy (auto-detected from prompt text):**
- For SSH FIDO2: `"ssh-fido:" + SHA256_fingerprint` or `"ssh-fido:" + key_path`
- For Git: `"git:" + normalized_url`
- For sudo: `"sudo:" + username`
- Generic: `"custom:" + hash_of_prompt`

#### 2. `askpass-client`

Binary that serves as SSH_ASKPASS, GIT_ASKPASS, SUDO_ASKPASS. **Handles all user interaction** including the password dialog.

**Key Design Decision:** The client inherits display environment (`DISPLAY`, `WAYLAND_DISPLAY`) from the calling process (SSH, Git, sudo), ensuring dialogs appear in the correct graphical context.

**Behavior:**
1. Get prompt text from command-line argument (passed by SSH/Git/sudo)
2. Connect to daemon socket
3. Send `GetCredential` request with prompt text and `cache_id: "auto"`
4. If `Credential` response: Print to stdout, exit (cache hit)
5. If `CacheMiss` response:
   - Show GTK4 password dialog with "Remember for this session" checkbox
   - If user enters password and "Remember" is checked: Send `StoreCredential` to daemon
   - Print credential to stdout
6. Zero all memory, exit

**Fallback Mode:** If daemon is unavailable, client shows dialog and prints credential without caching.

**GTK4 Password Dialog:**
```rust
use gtk4::{Application, ApplicationWindow, Entry, CheckButton, Button};

// Dialog layout:
// - Prompt label (from SSH/Git/sudo)
// - Password entry (visibility: false)
// - "Remember for this session" checkbox (Alt+R mnemonic, checked by default)
// - Cancel / OK buttons

let remember_check = CheckButton::with_mnemonic("_Remember for this session");
remember_check.set_active(true);  // Checked by default
```

**Auto cache_id detection (in daemon):**
- Parses prompt text to determine type (SSH key fingerprint, Git URL, etc.)
- Falls back to hash of full prompt if unrecognized

#### 3. `askpass-cache-ctl`

Utility to list and manage cached credentials.

```bash
# List all cached credentials (metadata only, no secrets)
askpass-cache-ctl list

# Example output:
# ID       TYPE   CACHE ID                               TTL
# a7f3b2c1 ssh    ssh-fido:SHA256:xK3NvbHvA5N6TjXd...   24m 30s
# f2e8d1a0 git    git:https://github.com                1h 45m

# Delete by short ID
askpass-cache-ctl delete a7f3b2c1

# Delete all cached credentials
askpass-cache-ctl delete --all

# Delete by type
askpass-cache-ctl delete --type ssh
askpass-cache-ctl delete --type git

# Check daemon status
askpass-cache-ctl ping
```

### Testing Strategy

The architecture enables comprehensive testing with **daemon tests requiring NO display server**.

#### Unit Tests (No External Dependencies)

Test core modules in complete isolation:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn cache_stores_and_retrieves_credential() {
        let mut cache = CredentialCache::new();
        cache.insert("test-key", SecretString::from("test-password"), 
                     Duration::from_secs(60), CacheType::Custom);
        
        let retrieved = cache.get("test-key").unwrap();
        assert_eq!(retrieved.secret().expose_secret(), "test-password");
    }
    
    #[test]
    fn cache_expires_after_ttl() {
        // Test TTL expiry logic without any I/O
    }
    
    #[test]
    fn protocol_parses_valid_request() {
        let json = r#"{"type":"get_credential","prompt":"test"}"#;
        let request = Request::parse(json).unwrap();
        // Verify request fields
    }
}
```

**Target:** >80% coverage of `secure-askpass-core` and `secure-askpass-daemon`

#### Daemon Tests (No Display Required)

Test daemon request handling without GTK:

```rust
#[tokio::test]
async fn daemon_returns_cache_miss_when_not_cached() {
    let socket = ManualSocketProvider::new(&socket_path);
    let daemon = Daemon::new(socket);
    
    let cache = Arc::clone(daemon.cache());
    let request = Request::GetCredential {
        prompt: "Enter password".to_string(),
        cache_id: "test-key".to_string(),
        cache_type: None,
    };
    
    let response = daemon.handle_request(request, cache).await;
    assert!(matches!(response, Response::CacheMiss { .. }));
}

#[tokio::test]
async fn daemon_returns_cached_credential() {
    // Pre-populate cache, verify credential returned
}

#[tokio::test]
async fn daemon_stores_credential_from_client() {
    // Test StoreCredential request handling
}
```

**Key Benefit:** Daemon tests run fast without Xvfb because daemon has no UI.

#### Client Tests (Require Xvfb)

GTK dialog tests require a display server:

```bash
# Run client tests with Xvfb
xvfb-run cargo test -p askpass-client
```

#### Property-Based Tests

Use `proptest` for cache_id detection and protocol robustness:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn detect_cache_id_never_panics(prompt in ".*") {
        let _ = detect_cache_id(&prompt);
    }
    
    #[test]
    fn cache_id_is_deterministic(prompt in ".*") {
        let result1 = detect_cache_id(&prompt);
        let result2 = detect_cache_id(&prompt);
        prop_assert_eq!(result1.cache_id, result2.cache_id);
    }
    
    #[test]
    fn ssh_prompts_detected(key_type in "(ECDSA-SK|ED25519-SK)") {
        let prompt = format!("Enter PIN for {} key SHA256:abc123:", key_type);
        let result = detect_cache_id(&prompt);
        prop_assert_eq!(result.cache_type, CacheType::Ssh);
    }
}
```

#### Security Tests

Verify security properties:

```rust
#[test]
fn credential_is_zeroized_on_drop() {
    // SecretString auto-zeros via secrecy crate
}

#[test]
fn cache_memory_is_mlocked() {
    // Verify mlock was attempted on cache region
}

#[test]
fn debug_output_redacts_secrets() {
    let cred = CachedCredential::new(SecretString::from("secret"), ...);
    let debug = format!("{:?}", cred);
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("secret"));
}
```

**Additional Security Testing:**
- **Fuzzing**: Use `cargo-fuzz` to fuzz protocol parser
- **Memory leak detection**: Run with valgrind/ASAN
- **Miri**: Test unsafe code with `cargo miri test`
- **cargo-audit**: Automated vulnerability scanning in CI

#### Test Organization

```
crates/
├── secure-askpass-core/src/
│   ├── cache.rs          # Unit tests inline (no deps)
│   ├── cache_id.rs       # Unit + proptest tests inline
│   ├── protocol.rs       # Unit tests inline
│   └── traits.rs         # Unit tests inline
├── secure-askpass-daemon/src/
│   └── daemon.rs         # Integration tests inline (no display needed)
└── askpass-client/src/
    └── main.rs           # Unit tests inline (GTK tests need Xvfb)
```

**CI Pipeline:**

```yaml
# .github/workflows/test.yml
- cargo test -p secure-askpass-core    # Fast, no deps
- cargo test -p secure-askpass-daemon  # Fast, no display
- xvfb-run cargo test -p askpass-client # Needs Xvfb
- cargo clippy -- -D warnings
- cargo fmt --check
- cargo audit
```

### Protocol

Simple JSON over Unix socket (newline-delimited).

#### Request Types

**GetCredential (client -> daemon):**
```json
{
  "type": "get_credential",
  "prompt": "Enter PIN for ECDSA-SK key /home/user/.ssh/id_ecdsa_sk:",
  "cache_id": "auto",
  "cache_type": "ssh"
}
```

Fields:
- `type`: Always `"get_credential"`
- `prompt`: The prompt text (used for auto-detection if `cache_id` is `"auto"`)
- `cache_id`: Cache key (`"auto"` = auto-detect from prompt, or explicit key)
- `cache_type`: Optional type override (`"ssh"`, `"git"`, `"sudo"`, `"custom"`)

**StoreCredential (client -> daemon):**
```json
{
  "type": "store_credential",
  "cache_id": "ssh-fido:SHA256:abc123",
  "value": "123456",
  "cache_type": "ssh",
  "ttl": 1800
}
```

Fields:
- `type`: Always `"store_credential"`
- `cache_id`: The cache key (from `CacheMiss` response)
- `value`: The credential to store
- `cache_type`: Optional type (from `CacheMiss` response)
- `ttl`: Optional TTL override in seconds

**ClearCache (client -> daemon):**
```json
{
  "type": "clear_cache",
  "cache_id": "all",
  "cache_type": "ssh"
}
```

Fields:
- `cache_id`: `"all"` to clear all, or specific cache ID
- `cache_type`: Optional, clear only entries of this type

**Ping (health check):**
```json
{"type": "ping"}
```

#### Response Types

**Credential (cache hit):**
```json
{
  "type": "credential",
  "value": "123456"
}
```

**CacheMiss (client should prompt user):**
```json
{
  "type": "cache_miss",
  "cache_id": "ssh-fido:SHA256:abc123",
  "cache_type": "ssh"
}
```

The client should:
1. Show password dialog to user
2. If user enters password and wants to remember: Send `StoreCredential` with the returned `cache_id` and `cache_type`
3. Print credential to stdout

**Stored (confirmation):**
```json
{"type": "stored"}
```

**CacheCleared:**
```json
{
  "type": "cache_cleared",
  "count": 3
}
```

**Error:**
```json
{
  "type": "error",
  "code": "cancelled",
  "message": "User cancelled the prompt"
}
```

Error codes: `cancelled`, `invalid_request`, `internal_error`, `shutting_down`

**Pong:**
```json
{"type": "pong"}
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
# Global cache defaults
[cache]
default_ttl = 3600          # Default TTL: 1 hour
max_ttl = 86400             # Maximum allowed TTL: 24 hours
clear_on_lock = true        # Default: clear all caches on screen lock
clear_on_suspend = true     # Default: clear all caches on suspend

# SSH-specific configuration
[cache.ssh]
default_ttl = 1800          # 30 minutes (more security-critical)
max_ttl = 7200              # Max 2 hours
clear_on_lock = true        # Always clear SSH credentials on lock
clear_on_suspend = true     # Always clear on suspend

# Git-specific configuration
[cache.git]
default_ttl = 7200          # 2 hours (convenience for frequent commits/pushes)
max_ttl = 28800             # Max 8 hours
clear_on_lock = false       # Keep cached during quick lock/unlock
clear_on_suspend = true     # But clear on suspend

# Sudo-specific configuration
[cache.sudo]
default_ttl = 300           # 5 minutes (very sensitive)
max_ttl = 900               # Max 15 minutes
clear_on_lock = true        # Always clear sudo credentials
clear_on_suspend = true     # Always clear on suspend

# Custom cache entries inherit from [cache] defaults
# unless user specifies a cache_type in the request

[prompt]
# Timeout for user response (seconds)
timeout = 30

# Default state of "remember for session" checkbox
default_remember = true

[security]
# Encrypt cached credentials with session key (AES-256-GCM)
encrypt_cache = true

# Require user confirmation even for cached credentials
# (shows brief "Using cached credential" notification)
# Note: Per design decision, default is silent (false)
confirm_cached = false
```

**Configuration Precedence:**

1. Request-specific TTL (if provided by client)
2. Cache-type-specific config (e.g., `[cache.ssh]`)
3. Global defaults (`[cache]`)
4. Hardcoded fallbacks (1 hour TTL, clear on lock/suspend)

**Cache Type Detection:**

Cache types are determined by `cache_id` prefix:
- `ssh-fido:*` → `cache.ssh`
- `git:*` → `cache.git`
- `sudo:*` → `cache.sudo`
- `custom:*` → `cache` (global defaults)

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

#### Phase 1: Core Infrastructure (COMPLETE)
- [x] Define core traits (`SocketProvider`, `EventMonitor`)
- [x] Implement secure cache module (mlock, `SecretString`, TTL)
- [x] Implement protocol module (JSON over Unix socket)
- [x] Implement cache_id auto-detection from prompt text
- [x] Basic daemon with request handling (GetCredential, StoreCredential, ClearCache)
- [x] `askpass-client` binary with GTK4 dialog
- [x] "Remember for this session" checkbox (Alt+R mnemonic)
- [x] Unit tests for cache, protocol, and cache_id modules
- [x] Property-based tests (proptest) for cache_id detection
- [x] Works as SSH_ASKPASS, GIT_ASKPASS, SUDO_ASKPASS

#### Phase 2: NixOS Integration (COMPLETE)
- [x] Nix package derivation
- [x] Home-manager module with configuration options
- [x] Systemd user service with security hardening
- [x] Environment variable setup (SSH_ASKPASS, GIT_ASKPASS, SUDO_ASKPASS)
- [x] Development shell (`nix develop`)

#### Phase 3: Configuration & Polish (IN PROGRESS)
- [ ] Configuration file parsing in daemon
- [ ] CLI arguments for daemon (`--config`, `--socket`, `--verbose`)
- [x] `askpass-cache-ctl` utility (list, delete, ping commands)
- [ ] Timeout with visual countdown in dialog
- [ ] Password visibility toggle in dialog

#### Phase 4: D-Bus Event Monitoring
- [ ] D-Bus event monitoring implementation (`EventMonitor` trait)
- [ ] Clear-on-lock integration (listen to `org.freedesktop.ScreenSaver`)
- [ ] Clear-on-suspend integration (listen to `org.freedesktop.login1`)
- [ ] Per-cache-type clearing policies

#### Phase 5: Security Hardening
- [ ] Optional AES-256-GCM encryption of cached credentials
- [ ] Security tests (memory leak detection, fuzzing protocol)
- [ ] Memory safety tests (valgrind, miri)
- [ ] CI pipeline (GitHub Actions)
- [ ] Automated security scanning (cargo-audit, cargo-deny)

#### Phase 6: Future Enhancements
- [ ] libadwaita UI upgrade (currently using plain GTK4)
- [ ] CLI-only fallback (feature flag: `ui-cli`, using rpassword)
- [ ] Keyboard grab on X11 for prompt security
- [ ] Wayland layer-shell hints for security
- [ ] Third-party security audit of core modules

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

### Design Decisions

#### Cached Credentials After Screen Unlock

**Decision:** Clear cache on screen lock by default, configurable per cache type

**Rationale:**
- Security-first approach: reduces window of credential exposure
- Matches GPG-agent's security model
- Per-type configuration allows users to balance security vs convenience
- FIDO2 hardware keys already provide physical security, so requiring re-entry after unlock is reasonable

**Implementation:** D-Bus listener for `org.freedesktop.ScreenSaver` signals (Phase 3)

**Configuration example:**
```toml
[cache.ssh]
clear_on_lock = true   # Strict for SSH

[cache.git]
clear_on_lock = false  # Keep during quick lock/unlock
```

#### Cache Expiry Strategy

**Decision:** TTL-based expiry with per-cache-type configuration

**Behavior:**
- Each cache entry has an independent TTL
- Expired entries are automatically cleared
- TTL is separate from event-based clearing (lock/suspend)
- User can configure different TTLs: SSH (30min), Git (2hr), sudo (5min)

**Implementation:** Background task checks expiry periodically; expired entries removed silently

#### Multi-Seat Support

**Decision:** Not required - single user session only

**Rationale:**
- Daemon runs as systemd user service (one per user)
- `$XDG_RUNTIME_DIR/secure-askpass/socket` is already user-isolated
- Multi-seat is automatically handled by systemd user sessions
- Desktop use case doesn't require additional complexity

#### Keyring Integration for Persistence

**Decision:** Memory-only caching, no persistent storage

**Rationale:**
- Session-only credentials are the core security model
- Persistent storage in GNOME Keyring defeats the purpose (any app can read via D-Bus)
- If user wants persistence, they can use native tools (ssh-agent, git-credential-store)
- Our value proposition is secure session caching, not persistent storage

#### Cache Clearing Notifications

**Decision:** Silent clearing (no user notifications)

**Rationale:**
- User notification on every cache clear would be noisy
- Next authentication prompt is sufficient feedback
- Silent operation matches GPG-agent behavior
- No security benefit from notification (user already knows they locked screen)

#### FIDO2 Touch-Only Prompts

**Decision:** Deferred to future enhancement (post-MVP)

**Rationale:**
- Edge case detection is non-trivial (prompt text parsing is fragile)
- Risk of breaking common workflows during MVP phase
- Can be added in Phase 6 (Polish) once core functionality is stable
- Current workaround: user can cancel dialog or enter empty string if no PIN needed
- **Future consideration:** Detect "touch" keywords in prompt, show different dialog type

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
