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

### Components

#### 1. `secure-askpass-daemon`

The main daemon process, started via systemd socket activation.

**Responsibilities:**
- Listen on Unix socket (`$XDG_RUNTIME_DIR/secure-askpass/socket`)
- Maintain credential cache in secure memory
- Show GTK4 password prompts when cache miss
- Handle TTL expiry and manual cache clearing

**Secure Memory Handling (Rust):**
```rust
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

**Cache Key Strategy:**
- For SSH FIDO2: Hash of `"ssh-fido:" + key_fingerprint`
- For Git: `"git:" + protocol + "://" + host`
- For sudo: `"sudo:" + username`
- Generic: `"custom:" + user-provided-id`

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
secrecy = "0.8"           # Secret<T> wrapper with zeroize
zeroize = "1.7"           # Explicit memory zeroing
memsec = "0.6"            # mlock/mprotect bindings

# Async runtime
tokio = { version = "1", features = ["full"] }

# IPC
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# GUI
gtk4 = "0.7"
libadwaita = "0.5"

# Config
toml = "0.8"
dirs = "5"                # XDG directories

# Crypto (optional, for encrypted cache)
aes-gcm = "0.10"
rand = "0.8"

# Logging
tracing = "0.1"
tracing-subscriber = "0.3"
```

### Implementation Phases

#### Phase 1: Core Daemon (MVP)
- [ ] Basic daemon with Unix socket
- [ ] In-memory cache with TTL
- [ ] Simple zenity-based prompts (temporary)
- [ ] `askpass-client` binary
- [ ] Works as SSH_ASKPASS

#### Phase 2: Proper GUI
- [ ] GTK4/libadwaita password dialog
- [ ] "Remember for session" checkbox
- [ ] Proper keyboard handling

#### Phase 3: Security Hardening
- [ ] mlock for cache memory
- [ ] Optional AES encryption of cache
- [ ] Clear-on-lock integration (D-Bus listen for screensaver)
- [ ] systemd hardening options

#### Phase 4: NixOS Integration
- [ ] Nix package derivation
- [ ] Home-manager module
- [ ] Integration with existing `modules/security.nix`

#### Phase 5: Polish
- [ ] Configuration file support
- [ ] `askpass-cache-clear` utility
- [ ] Documentation
- [ ] Tests

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
