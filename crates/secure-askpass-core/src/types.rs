//! Core types for secure-askpass.
//!
//! This module contains the fundamental data structures used throughout
//! the secure-askpass system, primarily cache type definitions.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The type of credential being cached.
///
/// Different cache types can have different TTL defaults and clearing policies
/// (e.g., clear SSH credentials on screen lock but keep Git credentials).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CacheType {
    /// SSH FIDO2 key PINs (e.g., Yubikey)
    Ssh,
    /// Git credentials (HTTPS passwords, tokens)
    Git,
    /// Sudo password
    Sudo,
    /// Custom/unknown credential type
    Custom,
}

impl CacheType {
    /// Parse a cache type from a cache ID prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_askpass_core::types::CacheType;
    ///
    /// assert_eq!(CacheType::from_cache_id("ssh-fido:SHA256:abc"), CacheType::Ssh);
    /// assert_eq!(CacheType::from_cache_id("git:https://github.com"), CacheType::Git);
    /// assert_eq!(CacheType::from_cache_id("sudo:user"), CacheType::Sudo);
    /// assert_eq!(CacheType::from_cache_id("unknown:something"), CacheType::Custom);
    /// ```
    pub fn from_cache_id(cache_id: &str) -> Self {
        if cache_id.starts_with("ssh-fido:") || cache_id.starts_with("ssh:") {
            CacheType::Ssh
        } else if cache_id.starts_with("git:") {
            CacheType::Git
        } else if cache_id.starts_with("sudo:") {
            CacheType::Sudo
        } else {
            CacheType::Custom
        }
    }

    /// Returns the default TTL for this cache type.
    ///
    /// These are sensible defaults that balance security and convenience:
    /// - SSH: 30 minutes (security-critical)
    /// - Git: 2 hours (convenience for frequent commits)
    /// - Sudo: 5 minutes (very sensitive)
    /// - Custom: 1 hour (reasonable default)
    pub fn default_ttl(&self) -> Duration {
        match self {
            CacheType::Ssh => Duration::from_secs(30 * 60), // 30 minutes
            CacheType::Git => Duration::from_secs(2 * 60 * 60), // 2 hours
            CacheType::Sudo => Duration::from_secs(5 * 60), // 5 minutes
            CacheType::Custom => Duration::from_secs(60 * 60), // 1 hour
        }
    }

    /// Returns whether credentials of this type should be cleared on screen lock.
    pub fn clear_on_lock(&self) -> bool {
        match self {
            CacheType::Ssh => true,
            CacheType::Git => false, // Keep during quick lock/unlock
            CacheType::Sudo => true,
            CacheType::Custom => true,
        }
    }

    /// Returns whether credentials of this type should be cleared on suspend.
    pub fn clear_on_suspend(&self) -> bool {
        // All types clear on suspend by default
        true
    }
}

impl std::fmt::Display for CacheType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheType::Ssh => write!(f, "ssh"),
            CacheType::Git => write!(f, "git"),
            CacheType::Sudo => write!(f, "sudo"),
            CacheType::Custom => write!(f, "custom"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_type_from_cache_id() {
        assert_eq!(
            CacheType::from_cache_id("ssh-fido:SHA256:abc123"),
            CacheType::Ssh
        );
        assert_eq!(CacheType::from_cache_id("ssh:something"), CacheType::Ssh);
        assert_eq!(
            CacheType::from_cache_id("git:https://github.com"),
            CacheType::Git
        );
        assert_eq!(CacheType::from_cache_id("sudo:robert"), CacheType::Sudo);
        assert_eq!(CacheType::from_cache_id("custom:mykey"), CacheType::Custom);
        assert_eq!(CacheType::from_cache_id("unknown"), CacheType::Custom);
        assert_eq!(CacheType::from_cache_id(""), CacheType::Custom);
    }

    #[test]
    fn cache_type_display() {
        assert_eq!(CacheType::Ssh.to_string(), "ssh");
        assert_eq!(CacheType::Git.to_string(), "git");
        assert_eq!(CacheType::Sudo.to_string(), "sudo");
        assert_eq!(CacheType::Custom.to_string(), "custom");
    }

    #[test]
    fn cache_type_serde_roundtrip() {
        let types = [
            CacheType::Ssh,
            CacheType::Git,
            CacheType::Sudo,
            CacheType::Custom,
        ];
        for cache_type in types {
            let json = serde_json::to_string(&cache_type).unwrap();
            let parsed: CacheType = serde_json::from_str(&json).unwrap();
            assert_eq!(cache_type, parsed);
        }
    }

    #[test]
    fn cache_type_default_ttl() {
        assert_eq!(CacheType::Ssh.default_ttl(), Duration::from_secs(30 * 60));
        assert_eq!(
            CacheType::Git.default_ttl(),
            Duration::from_secs(2 * 60 * 60)
        );
        assert_eq!(CacheType::Sudo.default_ttl(), Duration::from_secs(5 * 60));
        assert_eq!(
            CacheType::Custom.default_ttl(),
            Duration::from_secs(60 * 60)
        );
    }

    #[test]
    fn cache_type_clear_policies() {
        assert!(CacheType::Ssh.clear_on_lock());
        assert!(!CacheType::Git.clear_on_lock());
        assert!(CacheType::Sudo.clear_on_lock());
        assert!(CacheType::Custom.clear_on_lock());

        // All types clear on suspend
        assert!(CacheType::Ssh.clear_on_suspend());
        assert!(CacheType::Git.clear_on_suspend());
        assert!(CacheType::Sudo.clear_on_suspend());
        assert!(CacheType::Custom.clear_on_suspend());
    }
}
