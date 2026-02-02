//! Configuration types and loading for askpass-cache.
//!
//! This module provides TOML configuration file support for the askpass-cache
//! daemon and client. Configuration is loaded from `~/.config/askpass-cache/config.toml`.
//!
//! # Error Handling
//!
//! - If the config file doesn't exist, default values are returned.
//! - If the config file exists but is invalid, an error is returned (fail fast).
//!
//! # Example Configuration
//!
//! ```toml
//! [cache]
//! default_ttl = 3600          # 1 hour
//! max_ttl = 86400             # 24 hours
//! clear_on_lock = true
//! clear_on_suspend = true
//!
//! [cache.ssh]
//! default_ttl = 1800          # 30 minutes
//! max_ttl = 7200              # 2 hours
//!
//! [cache.git]
//! default_ttl = 7200          # 2 hours
//! clear_on_lock = false       # Keep during quick lock/unlock
//!
//! [cache.sudo]
//! default_ttl = 300           # 5 minutes
//! max_ttl = 900               # 15 minutes
//!
//! [prompt]
//! timeout = 30
//! default_remember = true
//!
//! [security]
//! encrypt_cache = true        # Encrypt credentials in memory (default)
//! confirm_cached = false
//! ```

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use crate::types::CacheType;

/// Errors that can occur when loading configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failed to read the configuration file.
    #[error("Failed to read config file: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to parse the configuration file.
    #[error("Failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
}

/// Main configuration struct.
///
/// This is the top-level configuration that contains all settings for
/// askpass-cache. It can be loaded from a TOML file or created with
/// default values.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    /// Cache configuration.
    pub cache: CacheConfig,
    /// Prompt configuration.
    pub prompt: PromptConfig,
    /// Security configuration.
    pub security: SecurityConfig,
}

/// Configuration for credential caching.
///
/// Contains global defaults and per-type overrides for SSH, Git, and sudo.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Default TTL in seconds for credentials (default: 3600 = 1 hour).
    pub default_ttl: u64,
    /// Maximum TTL in seconds for credentials (default: 86400 = 24 hours).
    pub max_ttl: u64,
    /// Whether to clear cache on screen lock (default: true).
    pub clear_on_lock: bool,
    /// Whether to clear cache on suspend (default: true).
    pub clear_on_suspend: bool,
    /// SSH-specific configuration overrides.
    pub ssh: Option<CacheTypeConfig>,
    /// Git-specific configuration overrides.
    pub git: Option<CacheTypeConfig>,
    /// Sudo-specific configuration overrides.
    pub sudo: Option<CacheTypeConfig>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            default_ttl: 3600, // 1 hour
            max_ttl: 86400,    // 24 hours
            clear_on_lock: true,
            clear_on_suspend: true,
            ssh: None,
            git: None,
            sudo: None,
        }
    }
}

/// Per-type configuration overrides.
///
/// All fields are optional; when `None`, the global cache config or
/// built-in type defaults are used.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CacheTypeConfig {
    /// TTL in seconds for this cache type.
    pub default_ttl: Option<u64>,
    /// Maximum TTL in seconds for this cache type.
    pub max_ttl: Option<u64>,
    /// Whether to clear on screen lock for this cache type.
    pub clear_on_lock: Option<bool>,
    /// Whether to clear on suspend for this cache type.
    pub clear_on_suspend: Option<bool>,
}

/// Configuration for user prompts.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PromptConfig {
    /// Prompt timeout in seconds (default: 30).
    pub timeout: u64,
    /// Default state of "Remember" checkbox (default: true).
    pub default_remember: bool,
}

impl Default for PromptConfig {
    fn default() -> Self {
        Self {
            timeout: 30,
            default_remember: true,
        }
    }
}

/// Security-related configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Whether to encrypt cached credentials with AES-256-GCM.
    ///
    /// When enabled, credentials are encrypted before being stored in the cache
    /// using a session key that is generated at daemon startup and held in
    /// memory-locked storage. This protects against secrets being exposed
    /// if the cache memory is swapped to disk.
    pub encrypt_cache: bool,
    /// Whether to require confirmation before using cached credentials.
    pub confirm_cached: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            encrypt_cache: true,
            confirm_cached: false,
        }
    }
}

impl Config {
    /// Returns the default configuration file path.
    ///
    /// Returns `~/.config/askpass-cache/config.toml` using `dirs::config_dir()`,
    /// or `None` if the config directory cannot be determined.
    pub fn default_path() -> Option<PathBuf> {
        dirs::config_dir().map(|p| p.join("askpass-cache").join("config.toml"))
    }

    /// Load configuration from the default path.
    ///
    /// - Returns `Ok(Config::default())` if no config file exists.
    /// - Returns `Err` if the file exists but cannot be read or parsed.
    pub fn load() -> Result<Self, ConfigError> {
        match Self::default_path() {
            Some(path) if path.exists() => Self::load_from(&path),
            _ => Ok(Self::default()),
        }
    }

    /// Load configuration from a specific path.
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Get the effective TTL for a cache type.
    ///
    /// Resolution order:
    /// 1. Type-specific `default_ttl` from config (e.g., `[cache.ssh]`)
    /// 2. Built-in type defaults (SSH=1800, Git=7200, Sudo=300, Custom=global)
    /// 3. Global `default_ttl` from `[cache]` section
    pub fn ttl_for(&self, cache_type: CacheType) -> Duration {
        let type_config = self.get_type_config(cache_type);

        // Check type-specific config first
        if let Some(config) = type_config {
            if let Some(ttl) = config.default_ttl {
                return Duration::from_secs(ttl);
            }
        }

        // Fall back to built-in type defaults
        let default_secs = match cache_type {
            CacheType::Ssh => 1800,                      // 30 minutes
            CacheType::Git => 7200,                      // 2 hours
            CacheType::Sudo => 300,                      // 5 minutes
            CacheType::Custom => self.cache.default_ttl, // Use global default
        };

        Duration::from_secs(default_secs)
    }

    /// Get the effective maximum TTL for a cache type.
    ///
    /// Resolution order:
    /// 1. Type-specific `max_ttl` from config (e.g., `[cache.ssh]`)
    /// 2. Built-in type defaults (SSH=7200, Git=28800, Sudo=900, Custom=global)
    /// 3. Global `max_ttl` from `[cache]` section
    pub fn max_ttl_for(&self, cache_type: CacheType) -> Duration {
        let type_config = self.get_type_config(cache_type);

        // Check type-specific config first
        if let Some(config) = type_config {
            if let Some(max_ttl) = config.max_ttl {
                return Duration::from_secs(max_ttl);
            }
        }

        // Fall back to built-in type defaults
        let default_secs = match cache_type {
            CacheType::Ssh => 7200,                  // 2 hours
            CacheType::Git => 28800,                 // 8 hours
            CacheType::Sudo => 900,                  // 15 minutes
            CacheType::Custom => self.cache.max_ttl, // Use global default
        };

        Duration::from_secs(default_secs)
    }

    /// Get whether credentials of a type should be cleared on screen lock.
    ///
    /// Resolution order:
    /// 1. Type-specific `clear_on_lock` from config (e.g., `[cache.ssh]`)
    /// 2. Built-in type defaults (SSH=true, Git=false, Sudo=true, Custom=global)
    /// 3. Global `clear_on_lock` from `[cache]` section
    pub fn clear_on_lock_for(&self, cache_type: CacheType) -> bool {
        let type_config = self.get_type_config(cache_type);

        // Check type-specific config first
        if let Some(config) = type_config {
            if let Some(clear) = config.clear_on_lock {
                return clear;
            }
        }

        // Fall back to built-in type defaults
        match cache_type {
            CacheType::Ssh => true,
            CacheType::Git => false, // Keep during quick lock/unlock
            CacheType::Sudo => true,
            CacheType::Custom => self.cache.clear_on_lock,
        }
    }

    /// Get whether credentials of a type should be cleared on suspend.
    ///
    /// Resolution order:
    /// 1. Type-specific `clear_on_suspend` from config (e.g., `[cache.ssh]`)
    /// 2. Built-in type defaults (all types: true)
    /// 3. Global `clear_on_suspend` from `[cache]` section
    pub fn clear_on_suspend_for(&self, cache_type: CacheType) -> bool {
        let type_config = self.get_type_config(cache_type);

        // Check type-specific config first
        if let Some(config) = type_config {
            if let Some(clear) = config.clear_on_suspend {
                return clear;
            }
        }

        // All types clear on suspend by default
        self.cache.clear_on_suspend
    }

    /// Get the type-specific config for a cache type.
    fn get_type_config(&self, cache_type: CacheType) -> Option<&CacheTypeConfig> {
        match cache_type {
            CacheType::Ssh => self.cache.ssh.as_ref(),
            CacheType::Git => self.cache.git.as_ref(),
            CacheType::Sudo => self.cache.sudo.as_ref(),
            CacheType::Custom => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn default_config_values() {
        let config = Config::default();

        // Global cache defaults
        assert_eq!(config.cache.default_ttl, 3600);
        assert_eq!(config.cache.max_ttl, 86400);
        assert!(config.cache.clear_on_lock);
        assert!(config.cache.clear_on_suspend);

        // Prompt defaults
        assert_eq!(config.prompt.timeout, 30);
        assert!(config.prompt.default_remember);

        // Security defaults
        assert!(config.security.encrypt_cache);
        assert!(!config.security.confirm_cached);
    }

    #[test]
    fn load_nonexistent_file_returns_defaults() {
        let config = Config::load().expect("Should return defaults");
        assert_eq!(config.cache.default_ttl, 3600);
    }

    #[test]
    fn load_valid_config() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[cache]
default_ttl = 7200
max_ttl = 14400
clear_on_lock = false

[cache.ssh]
default_ttl = 900
max_ttl = 1800

[prompt]
timeout = 60
default_remember = false

[security]
encrypt_cache = false
confirm_cached = true
"#
        )
        .unwrap();

        let config = Config::load_from(file.path()).expect("Should parse");

        // Global overrides
        assert_eq!(config.cache.default_ttl, 7200);
        assert_eq!(config.cache.max_ttl, 14400);
        assert!(!config.cache.clear_on_lock);

        // SSH overrides
        let ssh = config.cache.ssh.as_ref().unwrap();
        assert_eq!(ssh.default_ttl, Some(900));
        assert_eq!(ssh.max_ttl, Some(1800));

        // Prompt overrides
        assert_eq!(config.prompt.timeout, 60);
        assert!(!config.prompt.default_remember);

        // Security overrides
        assert!(!config.security.encrypt_cache);
        assert!(config.security.confirm_cached);
    }

    #[test]
    fn load_partial_config_uses_defaults() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[cache.ssh]
default_ttl = 600
"#
        )
        .unwrap();

        let config = Config::load_from(file.path()).expect("Should parse");

        // Global should be defaults
        assert_eq!(config.cache.default_ttl, 3600);
        assert!(config.cache.clear_on_lock);

        // SSH should have override
        let ssh = config.cache.ssh.as_ref().unwrap();
        assert_eq!(ssh.default_ttl, Some(600));
        assert_eq!(ssh.max_ttl, None);
    }

    #[test]
    fn load_invalid_config_returns_error() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "this is not valid toml {{{{").unwrap();

        let result = Config::load_from(file.path());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::Parse(_)));
    }

    #[test]
    fn load_empty_config_returns_defaults() {
        let file = NamedTempFile::new().unwrap();
        let config = Config::load_from(file.path()).expect("Should parse empty file");

        assert_eq!(config.cache.default_ttl, 3600);
        assert!(config.prompt.default_remember);
    }

    #[test]
    fn ttl_for_uses_type_specific_config() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[cache.ssh]
default_ttl = 999
"#
        )
        .unwrap();

        let config = Config::load_from(file.path()).unwrap();

        // SSH should use type-specific value
        assert_eq!(config.ttl_for(CacheType::Ssh), Duration::from_secs(999));

        // Git should use built-in default (no config override)
        assert_eq!(config.ttl_for(CacheType::Git), Duration::from_secs(7200));
    }

    #[test]
    fn ttl_for_uses_builtin_defaults() {
        let config = Config::default();

        assert_eq!(config.ttl_for(CacheType::Ssh), Duration::from_secs(1800));
        assert_eq!(config.ttl_for(CacheType::Git), Duration::from_secs(7200));
        assert_eq!(config.ttl_for(CacheType::Sudo), Duration::from_secs(300));
        assert_eq!(config.ttl_for(CacheType::Custom), Duration::from_secs(3600));
    }

    #[test]
    fn max_ttl_for_uses_type_specific_config() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[cache.sudo]
max_ttl = 1200
"#
        )
        .unwrap();

        let config = Config::load_from(file.path()).unwrap();

        // Sudo should use type-specific value
        assert_eq!(
            config.max_ttl_for(CacheType::Sudo),
            Duration::from_secs(1200)
        );

        // SSH should use built-in default
        assert_eq!(
            config.max_ttl_for(CacheType::Ssh),
            Duration::from_secs(7200)
        );
    }

    #[test]
    fn max_ttl_for_uses_builtin_defaults() {
        let config = Config::default();

        assert_eq!(
            config.max_ttl_for(CacheType::Ssh),
            Duration::from_secs(7200)
        );
        assert_eq!(
            config.max_ttl_for(CacheType::Git),
            Duration::from_secs(28800)
        );
        assert_eq!(
            config.max_ttl_for(CacheType::Sudo),
            Duration::from_secs(900)
        );
        assert_eq!(
            config.max_ttl_for(CacheType::Custom),
            Duration::from_secs(86400)
        );
    }

    #[test]
    fn clear_on_lock_for_uses_type_specific_config() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[cache.git]
clear_on_lock = true
"#
        )
        .unwrap();

        let config = Config::load_from(file.path()).unwrap();

        // Git should use type-specific value (overriding default false)
        assert!(config.clear_on_lock_for(CacheType::Git));

        // SSH should use built-in default
        assert!(config.clear_on_lock_for(CacheType::Ssh));
    }

    #[test]
    fn clear_on_lock_for_uses_builtin_defaults() {
        let config = Config::default();

        assert!(config.clear_on_lock_for(CacheType::Ssh));
        assert!(!config.clear_on_lock_for(CacheType::Git)); // Git is special
        assert!(config.clear_on_lock_for(CacheType::Sudo));
        assert!(config.clear_on_lock_for(CacheType::Custom));
    }

    #[test]
    fn clear_on_suspend_for_uses_type_specific_config() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[cache.git]
clear_on_suspend = false
"#
        )
        .unwrap();

        let config = Config::load_from(file.path()).unwrap();

        // Git should use type-specific value
        assert!(!config.clear_on_suspend_for(CacheType::Git));

        // SSH should use global default (true)
        assert!(config.clear_on_suspend_for(CacheType::Ssh));
    }

    #[test]
    fn clear_on_suspend_for_uses_global_default() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[cache]
clear_on_suspend = false
"#
        )
        .unwrap();

        let config = Config::load_from(file.path()).unwrap();

        // All types should use global setting
        assert!(!config.clear_on_suspend_for(CacheType::Ssh));
        assert!(!config.clear_on_suspend_for(CacheType::Git));
        assert!(!config.clear_on_suspend_for(CacheType::Sudo));
        assert!(!config.clear_on_suspend_for(CacheType::Custom));
    }

    #[test]
    fn custom_type_uses_global_config() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[cache]
default_ttl = 5000
max_ttl = 10000
clear_on_lock = false
"#
        )
        .unwrap();

        let config = Config::load_from(file.path()).unwrap();

        // Custom type should use global config values
        assert_eq!(config.ttl_for(CacheType::Custom), Duration::from_secs(5000));
        assert_eq!(
            config.max_ttl_for(CacheType::Custom),
            Duration::from_secs(10000)
        );
        assert!(!config.clear_on_lock_for(CacheType::Custom));
    }

    #[test]
    fn default_path_returns_config_dir() {
        let path = Config::default_path();
        assert!(path.is_some());
        let path = path.unwrap();
        assert!(path.ends_with("askpass-cache/config.toml"));
    }

    #[test]
    fn full_example_config() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[cache]
default_ttl = 3600
max_ttl = 86400
clear_on_lock = true
clear_on_suspend = true

[cache.ssh]
default_ttl = 1800
max_ttl = 7200
clear_on_lock = true
clear_on_suspend = true

[cache.git]
default_ttl = 7200
max_ttl = 28800
clear_on_lock = false
clear_on_suspend = true

[cache.sudo]
default_ttl = 300
max_ttl = 900
clear_on_lock = true
clear_on_suspend = true

[prompt]
timeout = 30
default_remember = true

[security]
encrypt_cache = true
confirm_cached = false
"#
        )
        .unwrap();

        let config = Config::load_from(file.path()).expect("Should parse full config");

        // Verify all values are loaded correctly
        assert_eq!(config.ttl_for(CacheType::Ssh), Duration::from_secs(1800));
        assert_eq!(config.ttl_for(CacheType::Git), Duration::from_secs(7200));
        assert_eq!(config.ttl_for(CacheType::Sudo), Duration::from_secs(300));

        assert_eq!(
            config.max_ttl_for(CacheType::Ssh),
            Duration::from_secs(7200)
        );
        assert_eq!(
            config.max_ttl_for(CacheType::Git),
            Duration::from_secs(28800)
        );
        assert_eq!(
            config.max_ttl_for(CacheType::Sudo),
            Duration::from_secs(900)
        );

        assert!(config.clear_on_lock_for(CacheType::Ssh));
        assert!(!config.clear_on_lock_for(CacheType::Git));
        assert!(config.clear_on_lock_for(CacheType::Sudo));

        assert_eq!(config.prompt.timeout, 30);
        assert!(config.prompt.default_remember);

        assert!(config.security.encrypt_cache);
        assert!(!config.security.confirm_cached);
    }
}
