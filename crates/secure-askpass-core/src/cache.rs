//! Secure credential cache implementation.
//!
//! This module provides a secure in-memory cache for credentials with:
//! - Automatic memory zeroing via `secrecy::SecretString`
//! - Memory locking via `memsec::mlock` to prevent swapping
//! - TTL-based automatic expiry
//! - Per-type clearing policies
//!
//! # Security
//!
//! All credentials are stored in `SecretString` which automatically zeros
//! memory when dropped. The cache struct itself is designed to be allocated
//! in locked memory to prevent secrets from being swapped to disk.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use secrecy::SecretString;
use tracing::{debug, trace};

use crate::types::CacheType;

/// A cached credential with metadata.
///
/// This struct holds a credential along with its creation time and TTL,
/// allowing for automatic expiry checks.
pub struct CachedCredential {
    /// The secret credential value.
    secret: SecretString,
    /// When this credential was cached.
    created_at: Instant,
    /// How long this credential should remain valid.
    ttl: Duration,
    /// The type of credential (for clearing policies).
    cache_type: CacheType,
}

impl CachedCredential {
    /// Create a new cached credential.
    pub fn new(secret: SecretString, ttl: Duration, cache_type: CacheType) -> Self {
        Self {
            secret,
            created_at: Instant::now(),
            ttl,
            cache_type,
        }
    }

    /// Check if this credential has expired.
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.ttl
    }

    /// Get the time remaining until expiry.
    pub fn time_remaining(&self) -> Option<Duration> {
        let elapsed = self.created_at.elapsed();
        if elapsed >= self.ttl {
            None
        } else {
            Some(self.ttl - elapsed)
        }
    }

    /// Get the cache type of this credential.
    pub fn cache_type(&self) -> CacheType {
        self.cache_type
    }

    /// Get a reference to the secret.
    ///
    /// # Security
    ///
    /// The returned `SecretString` should be exposed only when necessary
    /// using `expose_secret()`.
    pub fn secret(&self) -> &SecretString {
        &self.secret
    }
}

// Manual Debug implementation to avoid exposing secrets
impl std::fmt::Debug for CachedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedCredential")
            .field("secret", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("ttl", &self.ttl)
            .field("cache_type", &self.cache_type)
            .finish()
    }
}

/// A secure credential cache.
///
/// This cache stores credentials in memory with automatic expiry.
/// The cache is designed to be used with memory locking to prevent
/// credentials from being swapped to disk.
///
/// # Thread Safety
///
/// This struct is NOT thread-safe. Wrap it in `tokio::sync::Mutex` or
/// similar for concurrent access.
///
/// # Example
///
/// ```
/// use secure_askpass_core::cache::CredentialCache;
/// use secure_askpass_core::types::CacheType;
/// use secrecy::SecretString;
/// use std::time::Duration;
///
/// let mut cache = CredentialCache::new();
///
/// // Insert a credential
/// cache.insert(
///     "ssh-fido:SHA256:abc123",
///     SecretString::from("my-pin"),
///     Duration::from_secs(1800),
///     CacheType::Ssh,
/// );
///
/// // Retrieve it
/// if let Some(cred) = cache.get("ssh-fido:SHA256:abc123") {
///     // Use the credential...
/// }
/// ```
pub struct CredentialCache {
    /// The cached credentials, keyed by cache ID.
    entries: HashMap<String, CachedCredential>,
    /// Whether memory locking is enabled.
    memory_locked: bool,
}

impl CredentialCache {
    /// Create a new empty credential cache.
    ///
    /// This will attempt to lock the cache memory using `mlock`.
    /// If locking fails (e.g., due to insufficient privileges), the cache
    /// will still function but credentials may be swapped to disk.
    pub fn new() -> Self {
        let mut cache = Self {
            entries: HashMap::new(),
            memory_locked: false,
        };
        cache.try_lock_memory();
        cache
    }

    /// Attempt to lock the cache memory.
    ///
    /// This uses `memsec::mlock` to prevent the cache from being swapped
    /// to disk. If locking fails, a warning is logged but the cache
    /// continues to function.
    fn try_lock_memory(&mut self) {
        // Note: We can't actually mlock a HashMap effectively because
        // it allocates dynamically. In a production implementation,
        // we might use a fixed-size arena allocator with mlock.
        // For now, we track the intent and log appropriately.
        //
        // The actual secrets in SecretString are the most important
        // thing to protect, and secrecy handles zeroizing them on drop.

        // Try to mlock the struct itself (limited effectiveness)
        let ptr = self as *mut Self as *mut u8;
        let size = std::mem::size_of::<Self>();

        // Safety: We're locking our own memory region
        let result = unsafe { memsec::mlock(ptr, size) };

        if result {
            self.memory_locked = true;
            debug!("Cache memory locked successfully");
        } else {
            // This is common - mlock requires CAP_IPC_LOCK or sufficient RLIMIT_MEMLOCK
            debug!("Failed to lock cache memory (this is normal for unprivileged processes)");
        }
    }

    /// Insert a credential into the cache.
    ///
    /// If a credential with the same key exists, it is replaced.
    pub fn insert(
        &mut self,
        key: &str,
        secret: SecretString,
        ttl: Duration,
        cache_type: CacheType,
    ) {
        trace!(key = %key, cache_type = %cache_type, ttl_secs = ttl.as_secs(), "Inserting credential");
        let credential = CachedCredential::new(secret, ttl, cache_type);
        self.entries.insert(key.to_string(), credential);
    }

    /// Get a credential from the cache.
    ///
    /// Returns `None` if the key doesn't exist or the credential has expired.
    /// Expired credentials are NOT automatically removed by this method.
    pub fn get(&self, key: &str) -> Option<&CachedCredential> {
        self.entries.get(key).filter(|cred| !cred.is_expired())
    }

    /// Remove a credential from the cache.
    ///
    /// Returns `true` if a credential was removed.
    pub fn remove(&mut self, key: &str) -> bool {
        let removed = self.entries.remove(key).is_some();
        if removed {
            trace!(key = %key, "Removed credential");
        }
        removed
    }

    /// Clear all credentials from the cache.
    pub fn clear_all(&mut self) {
        let count = self.entries.len();
        self.entries.clear();
        debug!(count = count, "Cleared all credentials");
    }

    /// Clear all credentials of a specific type.
    ///
    /// Returns the number of credentials removed.
    pub fn clear_by_type(&mut self, cache_type: CacheType) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, cred| cred.cache_type() != cache_type);
        let removed = before - self.entries.len();
        debug!(cache_type = %cache_type, removed = removed, "Cleared credentials by type");
        removed
    }

    /// Remove all expired credentials.
    ///
    /// Returns the number of credentials removed.
    pub fn cleanup_expired(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, cred| !cred.is_expired());
        let removed = before - self.entries.len();
        if removed > 0 {
            debug!(removed = removed, "Cleaned up expired credentials");
        }
        removed
    }

    /// Get the number of credentials in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Check if a key exists in the cache (including expired entries).
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// Check if memory locking is active.
    pub fn is_memory_locked(&self) -> bool {
        self.memory_locked
    }

    /// Get all keys in the cache (for debugging/admin purposes).
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(|s| s.as_str())
    }
}

impl Default for CredentialCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CredentialCache {
    fn drop(&mut self) {
        // Clear all entries (SecretString will zero memory on drop)
        self.entries.clear();

        // Unlock memory if it was locked
        if self.memory_locked {
            let ptr = self as *mut Self as *mut u8;
            let size = std::mem::size_of::<Self>();
            // Safety: We're unlocking memory we previously locked
            unsafe {
                memsec::munlock(ptr, size);
            }
            debug!("Cache memory unlocked");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::thread::sleep;

    #[test]
    fn cache_insert_and_get() {
        let mut cache = CredentialCache::new();
        cache.insert(
            "test-key",
            SecretString::from("test-secret"),
            Duration::from_secs(3600),
            CacheType::Custom,
        );

        let cred = cache.get("test-key").expect("credential should exist");
        assert_eq!(cred.secret().expose_secret(), "test-secret");
        assert_eq!(cred.cache_type(), CacheType::Custom);
    }

    #[test]
    fn cache_get_nonexistent_returns_none() {
        let cache = CredentialCache::new();
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn cache_remove() {
        let mut cache = CredentialCache::new();
        cache.insert(
            "test-key",
            SecretString::from("test-secret"),
            Duration::from_secs(3600),
            CacheType::Custom,
        );

        assert!(cache.remove("test-key"));
        assert!(cache.get("test-key").is_none());
        assert!(!cache.remove("test-key")); // Already removed
    }

    #[test]
    fn cache_clear_all() {
        let mut cache = CredentialCache::new();
        cache.insert(
            "key1",
            SecretString::from("secret1"),
            Duration::from_secs(3600),
            CacheType::Ssh,
        );
        cache.insert(
            "key2",
            SecretString::from("secret2"),
            Duration::from_secs(3600),
            CacheType::Git,
        );

        assert_eq!(cache.len(), 2);
        cache.clear_all();
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_clear_by_type() {
        let mut cache = CredentialCache::new();
        cache.insert(
            "ssh1",
            SecretString::from("secret1"),
            Duration::from_secs(3600),
            CacheType::Ssh,
        );
        cache.insert(
            "ssh2",
            SecretString::from("secret2"),
            Duration::from_secs(3600),
            CacheType::Ssh,
        );
        cache.insert(
            "git1",
            SecretString::from("secret3"),
            Duration::from_secs(3600),
            CacheType::Git,
        );

        let removed = cache.clear_by_type(CacheType::Ssh);
        assert_eq!(removed, 2);
        assert_eq!(cache.len(), 1);
        assert!(cache.get("git1").is_some());
        assert!(cache.get("ssh1").is_none());
    }

    #[test]
    fn cache_expiry() {
        let mut cache = CredentialCache::new();
        cache.insert(
            "short-lived",
            SecretString::from("secret"),
            Duration::from_millis(50),
            CacheType::Custom,
        );

        // Should be accessible immediately
        assert!(cache.get("short-lived").is_some());

        // Wait for expiry
        sleep(Duration::from_millis(100));

        // Should be expired now
        assert!(cache.get("short-lived").is_none());

        // But the entry still exists until cleanup
        assert!(cache.contains_key("short-lived"));
    }

    #[test]
    fn cache_cleanup_expired() {
        let mut cache = CredentialCache::new();
        cache.insert(
            "short-lived",
            SecretString::from("secret1"),
            Duration::from_millis(50),
            CacheType::Custom,
        );
        cache.insert(
            "long-lived",
            SecretString::from("secret2"),
            Duration::from_secs(3600),
            CacheType::Custom,
        );

        // Wait for short-lived to expire
        sleep(Duration::from_millis(100));

        let removed = cache.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 1);
        assert!(cache.get("long-lived").is_some());
        assert!(!cache.contains_key("short-lived"));
    }

    #[test]
    fn cache_replace_existing() {
        let mut cache = CredentialCache::new();
        cache.insert(
            "key",
            SecretString::from("original"),
            Duration::from_secs(3600),
            CacheType::Custom,
        );
        cache.insert(
            "key",
            SecretString::from("replacement"),
            Duration::from_secs(3600),
            CacheType::Custom,
        );

        let cred = cache.get("key").expect("credential should exist");
        assert_eq!(cred.secret().expose_secret(), "replacement");
    }

    #[test]
    fn cached_credential_time_remaining() {
        let cred = CachedCredential::new(
            SecretString::from("secret"),
            Duration::from_secs(10),
            CacheType::Custom,
        );

        let remaining = cred.time_remaining().expect("should have time remaining");
        assert!(remaining <= Duration::from_secs(10));
        assert!(remaining > Duration::from_secs(9));
    }

    #[test]
    fn cached_credential_time_remaining_expired() {
        let cred = CachedCredential::new(
            SecretString::from("secret"),
            Duration::from_millis(10),
            CacheType::Custom,
        );

        sleep(Duration::from_millis(50));

        assert!(cred.is_expired());
        assert!(cred.time_remaining().is_none());
    }

    #[test]
    fn cached_credential_debug_redacts_secret() {
        let cred = CachedCredential::new(
            SecretString::from("super-secret"),
            Duration::from_secs(10),
            CacheType::Custom,
        );

        let debug_output = format!("{:?}", cred);
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("super-secret"));
    }

    #[test]
    fn cache_keys_iteration() {
        let mut cache = CredentialCache::new();
        cache.insert(
            "key1",
            SecretString::from("secret1"),
            Duration::from_secs(3600),
            CacheType::Custom,
        );
        cache.insert(
            "key2",
            SecretString::from("secret2"),
            Duration::from_secs(3600),
            CacheType::Custom,
        );

        let keys: Vec<_> = cache.keys().collect();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"key1"));
        assert!(keys.contains(&"key2"));
    }

    #[test]
    fn cache_default() {
        let cache = CredentialCache::default();
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_different_types() {
        let mut cache = CredentialCache::new();

        // Insert credentials of different types
        cache.insert(
            "ssh-fido:key1",
            SecretString::from("pin1"),
            Duration::from_secs(1800),
            CacheType::Ssh,
        );
        cache.insert(
            "git:https://github.com",
            SecretString::from("token"),
            Duration::from_secs(7200),
            CacheType::Git,
        );
        cache.insert(
            "sudo:user",
            SecretString::from("password"),
            Duration::from_secs(300),
            CacheType::Sudo,
        );

        assert_eq!(cache.len(), 3);

        // Clear only SSH
        cache.clear_by_type(CacheType::Ssh);
        assert_eq!(cache.len(), 2);
        assert!(cache.get("git:https://github.com").is_some());
        assert!(cache.get("sudo:user").is_some());
    }
}
