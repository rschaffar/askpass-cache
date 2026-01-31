# Implementation Plan: secure-askpass Phase 1

This document tracks the Phase 1 (MVP) implementation of secure-askpass.

## Design Decisions

Based on initial planning, we chose:

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Implementation order** | Bottom-up | Types → Cache → Protocol → Daemon → Client. Allows testing each layer independently |
| **Phase 1 UI** | Simple GTK4 dialog | No throwaway code. Uses the `PasswordPrompt` trait from day one |
| **Socket activation** | Systemd from start | Production-ready foundation. Manual fallback for development |

## Implementation Steps

### Step 1: Core Types (`secure-askpass-core`)

**Goal:** Define all shared types and traits that other modules depend on.

**Files to create:**
- `crates/secure-askpass-core/src/types.rs` - Core enums and structs
- `crates/secure-askpass-core/src/protocol.rs` - Request/Response types
- `crates/secure-askpass-core/src/traits.rs` - `PasswordPrompt`, `SocketProvider`, `EventMonitor`
- `crates/secure-askpass-core/src/lib.rs` - Module exports

**Types to implement:**
```rust
// types.rs
pub enum CacheType { Ssh, Git, Sudo, Custom }

pub struct PromptConfig {
    pub prompt_text: String,
    pub cache_id: String,
    pub cache_type: CacheType,
    pub timeout: Duration,
    pub show_remember_checkbox: bool,
}

pub struct PromptResponse {
    pub credential: Secret<String>,
    pub should_cache: bool,
}

// protocol.rs
pub enum Request {
    GetCredential { prompt, cache_id, cache_type, ttl, allow_cache, echo },
    ClearCache { cache_id },
}

pub enum Response {
    Credential { value: Secret<String>, from_cache: bool },
    Error { code: ErrorCode, message: String },
    CacheCleared,
}

pub enum ErrorCode { Cancelled, Timeout, InvalidRequest, InternalError }

// traits.rs
pub trait PasswordPrompt: Send + Sync {
    async fn prompt(&self, config: PromptConfig) -> Result<PromptResponse>;
}

pub trait SocketProvider: Send + Sync {
    async fn listen(&self) -> Result<UnixListener>;
}

pub trait EventMonitor: Send + Sync {
    async fn next_event(&mut self) -> Option<SystemEvent>;
}

pub enum SystemEvent { ScreenLocked, ScreenUnlocked, Suspend, Resume }
```

**Tests:**
- [ ] Serde round-trip for `Request` and `Response`
- [ ] `CacheType` parsing from string prefixes
- [ ] `ErrorCode` serialization

**Dependencies:** `serde`, `serde_json`, `secrecy`, `thiserror`, `tokio`

---

### Step 2: Secure Cache (`secure-askpass-core`)

**Goal:** Implement the credential cache with secure memory handling.

**Files to create:**
- `crates/secure-askpass-core/src/cache.rs` - `CredentialCache` implementation

**Implementation:**
```rust
pub struct CachedCredential {
    secret: Secret<String>,
    created_at: Instant,
    ttl: Duration,
    cache_type: CacheType,
}

pub struct CredentialCache {
    entries: HashMap<String, CachedCredential>,
    // Memory region is mlocked
}

impl CredentialCache {
    pub fn new() -> Self;
    pub fn insert(&mut self, key: &str, secret: Secret<String>, ttl: Duration, cache_type: CacheType);
    pub fn get(&self, key: &str) -> Option<&Secret<String>>;
    pub fn remove(&mut self, key: &str) -> bool;
    pub fn clear_all(&mut self);
    pub fn clear_by_type(&mut self, cache_type: CacheType);
    pub fn cleanup_expired(&mut self) -> usize;  // Returns count of removed entries
}
```

**Security requirements:**
- [ ] Use `Secret<String>` for all credential storage
- [ ] Call `memsec::mlock` on cache memory region
- [ ] Implement `Drop` to zero and unlock memory
- [ ] No `Debug` or `Display` that could leak secrets

**Tests:**
- [ ] Insert and retrieve credential
- [ ] Get returns `None` for unknown key
- [ ] Remove deletes entry
- [ ] TTL expiry (entry not returned after TTL)
- [ ] `cleanup_expired` removes only expired entries
- [ ] `clear_by_type` removes correct entries
- [ ] Concurrent access safety (with `tokio::sync::Mutex`)

**Dependencies:** `secrecy`, `zeroize`, `memsec`, `tokio`

---

### Step 3: Protocol Parser (`secure-askpass-core`)

**Goal:** Parse and serialize the JSON protocol, including cache ID auto-detection.

**Files to create:**
- `crates/secure-askpass-core/src/protocol.rs` - Extend with parsing logic
- `crates/secure-askpass-core/src/cache_id.rs` - Cache ID detection from prompts

**Cache ID auto-detection rules:**
```rust
// Detect from prompt text:
// "Enter PIN for ECDSA-SK key SHA256:abc123..." → "ssh-fido:SHA256:abc123..."
// "Password for 'https://github.com':" → "git:https://github.com"
// "[sudo] password for user:" → "sudo:user"
// Unrecognized → "custom:<hash-of-prompt>"

pub fn detect_cache_id(prompt: &str) -> (String, CacheType);
```

**Tests:**
- [ ] Parse valid `GetCredential` request
- [ ] Parse valid `ClearCache` request
- [ ] Invalid JSON returns `ErrorCode::InvalidRequest`
- [ ] Missing required fields return proper error
- [ ] Cache ID detection for SSH FIDO2 prompts
- [ ] Cache ID detection for Git credential prompts
- [ ] Cache ID detection for sudo prompts
- [ ] Unknown prompts get hashed cache ID
- [ ] **Proptest:** Arbitrary strings never panic the parser

**Dependencies:** `serde`, `serde_json`, `proptest` (dev)

---

### Step 4: Socket Provider (`secure-askpass-daemon`)

**Goal:** Implement systemd socket activation with manual fallback.

**Files to create:**
- `crates/secure-askpass-daemon/src/socket/mod.rs`
- `crates/secure-askpass-daemon/src/socket/systemd.rs`
- `crates/secure-askpass-daemon/src/socket/manual.rs`

**Implementation:**
```rust
// systemd.rs
pub struct SystemdSocketProvider;

impl SocketProvider for SystemdSocketProvider {
    async fn listen(&self) -> Result<UnixListener> {
        // Check LISTEN_FDS environment variable
        // If set, use file descriptor 3 (SD_LISTEN_FDS_START)
        // Otherwise, fall back to manual binding
    }
}

// manual.rs
pub struct ManualSocketProvider {
    path: PathBuf,
}

impl SocketProvider for ManualSocketProvider {
    async fn listen(&self) -> Result<UnixListener> {
        // Create directory if needed
        // Bind to $XDG_RUNTIME_DIR/secure-askpass/socket
        // Set mode 0600
    }
}
```

**Tests:**
- [ ] `LISTEN_FDS=1` uses inherited file descriptor
- [ ] Missing `LISTEN_FDS` falls back to manual binding
- [ ] Manual binding creates socket with correct permissions
- [ ] Socket directory created if missing

**Dependencies:** `tokio`, `sd-notify`, `dirs`

---

### Step 5: GTK4 Password Prompt (`secure-askpass-daemon`)

**Goal:** Implement a simple GTK4 dialog for password entry.

**Files to create:**
- `crates/secure-askpass-daemon/src/prompt/mod.rs`
- `crates/secure-askpass-daemon/src/prompt/gtk4.rs`
- `crates/secure-askpass-daemon/src/prompt/mock.rs` (for testing)

**Implementation:**
```rust
// gtk4.rs
pub struct Gtk4PasswordPrompt;

impl PasswordPrompt for Gtk4PasswordPrompt {
    async fn prompt(&self, config: PromptConfig) -> Result<PromptResponse> {
        // Create GTK4 dialog with:
        // - Title from config.prompt_text
        // - PasswordEntry widget
        // - "Remember for session" checkbox (if show_remember_checkbox)
        // - Cancel / Authenticate buttons
        // - Timeout handling
    }
}

// mock.rs (for testing)
pub struct MockPasswordPrompt {
    pub response: Option<PromptResponse>,
}

impl PasswordPrompt for MockPasswordPrompt {
    async fn prompt(&self, _config: PromptConfig) -> Result<PromptResponse> {
        self.response.clone().ok_or(Error::Cancelled)
    }
}
```

**Features:**
- [ ] Password entry with visibility toggle (eye icon)
- [ ] "Remember for session" checkbox
- [ ] Cancel and Authenticate buttons
- [ ] Timeout countdown (cancel after `config.timeout`)
- [ ] Proper async integration with tokio

**Tests:**
- [ ] Manual testing of dialog appearance
- [ ] Mock implementation for daemon tests
- [ ] Timeout triggers cancellation (integration test)

**Dependencies:** `gtk4`, `tokio`

---

### Step 6: Daemon Orchestration (`secure-askpass-daemon`)

**Goal:** Wire together cache, protocol, socket, and prompt into working daemon.

**Files to create/modify:**
- `crates/secure-askpass-daemon/src/main.rs` - Entry point
- `crates/secure-askpass-daemon/src/daemon.rs` - Core daemon logic
- `crates/secure-askpass-daemon/src/handler.rs` - Request handling

**Implementation:**
```rust
pub struct Daemon<P: PasswordPrompt, S: SocketProvider, E: EventMonitor> {
    cache: Arc<Mutex<CredentialCache>>,
    prompt: P,
    socket_provider: S,
    event_monitor: E,
}

impl<P, S, E> Daemon<P, S, E> {
    pub async fn run(&self) -> Result<()> {
        let listener = self.socket_provider.listen().await?;
        
        loop {
            tokio::select! {
                conn = listener.accept() => self.handle_connection(conn).await,
                event = self.event_monitor.next_event() => self.handle_event(event).await,
            }
        }
    }
    
    async fn handle_request(&self, request: Request) -> Response {
        match request {
            Request::GetCredential { cache_id, .. } => {
                // 1. Check cache
                // 2. If miss, show prompt
                // 3. If user allows caching, store in cache
                // 4. Return credential
            }
            Request::ClearCache { cache_id } => {
                // Clear specified entries
            }
        }
    }
}
```

**Tests (using mocks):**
- [ ] Cache hit returns credential without prompting
- [ ] Cache miss triggers prompt
- [ ] User cancellation returns error
- [ ] Prompt timeout returns error
- [ ] `should_cache=false` doesn't store credential
- [ ] `ClearCache` removes entries
- [ ] System events (lock) clear cache (when EventMonitor implemented)

**Dependencies:** `tokio`, `secure-askpass-core`

---

### Step 7: Client Binary (`askpass-client`)

**Goal:** Implement the thin client binary for SSH_ASKPASS/GIT_ASKPASS/SUDO_ASKPASS.

**Files to modify:**
- `crates/askpass-client/src/main.rs`

**Implementation:**
```rust
fn main() -> Result<()> {
    // 1. Get prompt from command line args or stdin
    let prompt = get_prompt()?;
    
    // 2. Connect to daemon socket
    let socket_path = get_socket_path();
    let mut stream = UnixStream::connect(&socket_path)?;
    
    // 3. Send request
    let request = Request::GetCredential {
        prompt: prompt.clone(),
        cache_id: "auto".to_string(),
        // ...
    };
    send_request(&mut stream, &request)?;
    
    // 4. Receive response
    let response = receive_response(&mut stream)?;
    
    // 5. Handle response
    match response {
        Response::Credential { value, .. } => {
            // Print to stdout (what SSH/Git expects)
            print!("{}", value.expose_secret());
            // Zero memory before exit
        }
        Response::Error { code, message } => {
            eprintln!("Error: {}", message);
            std::process::exit(1);
        }
    }
    
    Ok(())
}
```

**Security requirements:**
- [ ] Zero all buffers containing credentials before exit
- [ ] Use `Secret<String>` for received credentials
- [ ] No credential logging

**Tests:**
- [ ] E2E: Client connects to daemon, receives credential
- [ ] E2E: Client handles daemon error gracefully
- [ ] E2E: Client works with cached credential
- [ ] Verify memory zeroing (conceptual/manual test)

**Dependencies:** `secure-askpass-core`, `secrecy`, `zeroize`

---

## Test Strategy

### Principle: Test Each Step Before Moving On

This is a security-critical project. We must verify each layer before building on top.

### Test Types by Step

| Step | Test Type | Runner |
|------|-----------|--------|
| 1. Types | Unit tests | `cargo test -p secure-askpass-core` |
| 2. Cache | Unit tests (heavy) | `cargo test -p secure-askpass-core` |
| 3. Protocol | Unit + Proptest | `cargo test -p secure-askpass-core` |
| 4. Socket | Integration | `cargo test -p secure-askpass-daemon` |
| 5. GTK4 UI | Manual + Mock | Manual testing, mock for daemon tests |
| 6. Daemon | Integration (mocks) | `cargo test -p secure-askpass-daemon` |
| 7. Client | E2E | `cargo test --test e2e` |

### Test Commands

```bash
# Run all tests
cargo test

# Run specific crate tests
cargo test -p secure-askpass-core
cargo test -p secure-askpass-daemon
cargo test -p askpass-client

# Run with output (for debugging)
cargo test -- --nocapture

# Run proptest (longer)
cargo test -- --ignored  # if proptests are marked #[ignore]

# Run E2E tests (requires built binaries)
cargo build && cargo test --test e2e
```

### Coverage Goals

| Module | Target Coverage |
|--------|-----------------|
| `cache.rs` | >90% (security-critical) |
| `protocol.rs` | >90% (handles untrusted input) |
| `types.rs` | >80% |
| `daemon.rs` | >80% |
| `handler.rs` | >80% |
| GTK4 prompt | Manual testing |
| Client | E2E coverage |

---

## Progress Tracking

### Step 1: Core Types [COMPLETED]
- [x] Create `types.rs` with `CacheType`, `PromptConfig`, `PromptResponse`
- [x] Create `protocol.rs` with `Request`, `Response`, `ErrorCode`
- [x] Create `traits.rs` with `PasswordPrompt`, `SocketProvider`, `EventMonitor`
- [x] Update `lib.rs` with module exports
- [x] Add tests for serde round-trips
- [x] All tests passing (25 tests)

### Step 2: Secure Cache [COMPLETED]
- [x] Create `cache.rs` with `CachedCredential`, `CredentialCache`
- [x] Implement mlock for cache memory
- [x] Implement TTL-based expiry
- [x] Add unit tests for all operations
- [x] All tests passing (39 total tests)

### Step 3: Protocol Parser [COMPLETED]
- [x] Implement JSON parsing for requests/responses
- [x] Create `cache_id.rs` with auto-detection logic
- [x] Add proptest for parser robustness
- [x] All tests passing (67 total tests)

### Step 4: Socket Provider [COMPLETED]
- [x] Create socket module structure
- [x] Implement `SystemdSocketProvider`
- [x] Implement `ManualSocketProvider` fallback
- [x] Add integration tests
- [x] All tests passing (11 tests in daemon crate)

### Step 5: GTK4 Password Prompt [COMPLETED]
- [x] Create prompt module structure
- [x] Implement `Gtk4PasswordPrompt`
- [x] Implement `MockPasswordPrompt` for testing
- [x] Manual testing of dialog (requires display server)
- [x] All tests passing (92 total tests, 20 in daemon)

### Step 6: Daemon Orchestration [COMPLETED]
- [x] Create `daemon.rs` with `Daemon` struct
- [x] Integrated request handling in daemon module
- [x] Add integration tests with mocks
- [x] All tests passing (29 tests in daemon crate)

### Step 7: Client Binary [COMPLETED]
- [x] Implement `askpass-client` main
- [x] Socket connection and request handling
- [x] Proper credential output for SSH/Git/sudo
- [x] All tests passing (103 total tests)

---

## Definition of Done (Phase 1)

Phase 1 is complete when:

1. [ ] All 7 steps implemented with tests passing
2. [ ] `cargo clippy` reports no warnings
3. [ ] `cargo fmt --check` passes
4. [ ] Manual E2E test: SSH_ASKPASS works with FIDO2 key
5. [ ] Credentials are cached and returned on subsequent requests
6. [ ] Cache expires after TTL
7. [ ] User can cancel prompt
8. [ ] Code review of security-critical modules (cache, protocol)

---

## Notes

- **No libadwaita in Phase 1:** We use plain GTK4 to reduce complexity. libadwaita styling comes in Phase 2.
- **No config file in Phase 1:** Hardcoded defaults. Config parsing comes in Phase 3.
- **No D-Bus event monitoring in Phase 1:** `EventMonitor` trait exists but implementation is Phase 3.
- **No encrypted cache in Phase 1:** Plain `Secret<String>` with mlock. AES encryption is Phase 3.
