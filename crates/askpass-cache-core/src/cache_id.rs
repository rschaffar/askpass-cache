//! Cache ID auto-detection from prompt text.
//!
//! This module provides logic to automatically detect the type of credential
//! being requested and generate an appropriate cache ID from the prompt text.
//!
//! # Supported Prompt Formats
//!
//! ## SSH FIDO2 (Yubikey, etc.)
//! - `Enter PIN for ECDSA-SK key /path/to/key:`
//! - `Enter PIN for ED25519-SK key SHA256:...:`
//! - `Confirm user presence for key ECDSA-SK SHA256:...`
//!
//! ## Git Credentials
//! - `Password for 'https://github.com':`
//! - `Username for 'https://github.com':`
//!
//! ## Sudo
//! - `[sudo] password for username:`
//! - `Password:`
//!
//! # Cache ID Format
//!
//! - SSH: `ssh-fido:SHA256:...` or `ssh-fido:<key-path>`
//! - Git: `git:<url>`
//! - Sudo: `sudo:<username>`
//! - Custom: `custom:<sha256-of-prompt>`

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::types::CacheType;

/// Result of cache ID detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionResult {
    /// The detected or generated cache ID.
    pub cache_id: String,
    /// The detected cache type.
    pub cache_type: CacheType,
    /// Confidence level of the detection.
    pub confidence: Confidence,
}

/// Confidence level of cache ID detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// High confidence - prompt matched a known pattern exactly.
    High,
    /// Medium confidence - prompt partially matched a pattern.
    Medium,
    /// Low confidence - fallback to hash-based ID.
    Low,
}

/// Detect the cache ID and type from a prompt string.
///
/// # Arguments
///
/// * `prompt` - The prompt text from SSH_ASKPASS, GIT_ASKPASS, or SUDO_ASKPASS
///
/// # Returns
///
/// A `DetectionResult` containing the cache ID, type, and confidence level.
///
/// # Examples
///
/// ```
/// use askpass_cache_core::cache_id::detect_cache_id;
/// use askpass_cache_core::types::CacheType;
///
/// // SSH FIDO2 key
/// let result = detect_cache_id("Enter PIN for ECDSA-SK key SHA256:abc123...");
/// assert_eq!(result.cache_type, CacheType::Ssh);
/// assert!(result.cache_id.starts_with("ssh-fido:"));
///
/// // Git credentials
/// let result = detect_cache_id("Password for 'https://github.com':");
/// assert_eq!(result.cache_type, CacheType::Git);
/// assert!(result.cache_id.starts_with("git:"));
///
/// // Sudo
/// let result = detect_cache_id("[sudo] password for robert:");
/// assert_eq!(result.cache_type, CacheType::Sudo);
/// assert_eq!(result.cache_id, "sudo:robert");
/// ```
pub fn detect_cache_id(prompt: &str) -> DetectionResult {
    // Try each detector in order of specificity
    if let Some(result) = detect_ssh_fido(prompt) {
        return result;
    }

    if let Some(result) = detect_git(prompt) {
        return result;
    }

    if let Some(result) = detect_sudo(prompt) {
        return result;
    }

    // Fallback: hash the prompt
    fallback_hash(prompt)
}

/// Detect SSH FIDO2 key prompts.
///
/// Matches patterns like:
/// - "Enter PIN for ECDSA-SK key ..."
/// - "Enter PIN for ED25519-SK key ..."
/// - "Confirm user presence for key ..."
fn detect_ssh_fido(prompt: &str) -> Option<DetectionResult> {
    let prompt_lower = prompt.to_lowercase();

    // Check for FIDO2/SK key indicators
    let is_fido = prompt_lower.contains("ecdsa-sk")
        || prompt_lower.contains("ed25519-sk")
        || prompt_lower.contains("-sk key")
        || (prompt_lower.contains("pin") && prompt_lower.contains("key"));

    if !is_fido {
        return None;
    }

    // Try to extract SHA256 fingerprint
    if let Some(fingerprint) = extract_sha256_fingerprint(prompt) {
        return Some(DetectionResult {
            cache_id: format!("ssh-fido:{}", fingerprint),
            cache_type: CacheType::Ssh,
            confidence: Confidence::High,
        });
    }

    // Try to extract key path
    if let Some(path) = extract_key_path(prompt) {
        return Some(DetectionResult {
            cache_id: format!("ssh-fido:{}", path),
            cache_type: CacheType::Ssh,
            confidence: Confidence::High,
        });
    }

    // Matched FIDO pattern but couldn't extract identifier
    Some(DetectionResult {
        cache_id: format!("ssh-fido:{}", hash_string(prompt)),
        cache_type: CacheType::Ssh,
        confidence: Confidence::Medium,
    })
}

/// Detect Git credential prompts.
///
/// Matches patterns like:
/// - "Password for 'https://github.com':"
/// - "Username for 'https://github.com':"
fn detect_git(prompt: &str) -> Option<DetectionResult> {
    let prompt_lower = prompt.to_lowercase();

    // Check for Git credential patterns
    let is_git = (prompt_lower.contains("password for") || prompt_lower.contains("username for"))
        && (prompt_lower.contains("https://") || prompt_lower.contains("http://"));

    if !is_git {
        return None;
    }

    // Extract URL from quotes
    if let Some(url) = extract_quoted_url(prompt) {
        // Normalize the URL (remove trailing slash, etc.)
        let normalized = normalize_git_url(&url);
        return Some(DetectionResult {
            cache_id: format!("git:{}", normalized),
            cache_type: CacheType::Git,
            confidence: Confidence::High,
        });
    }

    // Try to extract URL without quotes
    if let Some(url) = extract_url(prompt) {
        let normalized = normalize_git_url(&url);
        return Some(DetectionResult {
            cache_id: format!("git:{}", normalized),
            cache_type: CacheType::Git,
            confidence: Confidence::Medium,
        });
    }

    None
}

/// Detect sudo password prompts.
///
/// Matches patterns like:
/// - "[sudo] password for username:"
/// - "Password:"
fn detect_sudo(prompt: &str) -> Option<DetectionResult> {
    let prompt_lower = prompt.to_lowercase();

    // Check for sudo pattern
    if prompt_lower.contains("[sudo]") {
        // Extract username
        if let Some(username) = extract_sudo_username(prompt) {
            return Some(DetectionResult {
                cache_id: format!("sudo:{}", username),
                cache_type: CacheType::Sudo,
                confidence: Confidence::High,
            });
        }

        // Sudo prompt without username
        return Some(DetectionResult {
            cache_id: "sudo:unknown".to_string(),
            cache_type: CacheType::Sudo,
            confidence: Confidence::Medium,
        });
    }

    // Generic "Password:" prompt (might be sudo)
    if prompt_lower.trim() == "password:" {
        return Some(DetectionResult {
            cache_id: "sudo:generic".to_string(),
            cache_type: CacheType::Sudo,
            confidence: Confidence::Low,
        });
    }

    None
}

/// Fallback: generate a hash-based cache ID.
fn fallback_hash(prompt: &str) -> DetectionResult {
    DetectionResult {
        cache_id: format!("custom:{}", hash_string(prompt)),
        cache_type: CacheType::Custom,
        confidence: Confidence::Low,
    }
}

/// Extract SHA256 fingerprint from prompt.
///
/// Looks for patterns like "SHA256:abc123..." or "SHA256:abc123/def456"
fn extract_sha256_fingerprint(prompt: &str) -> Option<String> {
    // Find "SHA256:" in the prompt
    let sha_prefix = "SHA256:";
    let start = prompt.find(sha_prefix)?;
    let after_prefix = &prompt[start + sha_prefix.len()..];

    // Extract the fingerprint (alphanumeric, +, /, =)
    let fingerprint: String = after_prefix
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .collect();

    if fingerprint.len() >= 8 {
        Some(format!("SHA256:{}", fingerprint))
    } else {
        None
    }
}

/// Extract key path from prompt.
///
/// Looks for patterns like "/home/user/.ssh/id_ecdsa_sk"
fn extract_key_path(prompt: &str) -> Option<String> {
    // Look for paths starting with / or ~
    for word in prompt.split_whitespace() {
        let word = word.trim_end_matches(':');
        if (word.starts_with('/') || word.starts_with('~')) && word.contains(".ssh") {
            return Some(word.to_string());
        }
    }
    None
}

/// Extract a URL enclosed in single quotes.
fn extract_quoted_url(prompt: &str) -> Option<String> {
    let start = prompt.find('\'')?;
    let rest = &prompt[start + 1..];
    let end = rest.find('\'')?;
    let url = &rest[..end];

    if url.starts_with("http://") || url.starts_with("https://") {
        Some(url.to_string())
    } else {
        None
    }
}

/// Extract a URL from the prompt (without quotes).
fn extract_url(prompt: &str) -> Option<String> {
    for word in prompt.split_whitespace() {
        let word =
            word.trim_matches(|c: char| !c.is_alphanumeric() && c != ':' && c != '/' && c != '.');
        if word.starts_with("http://") || word.starts_with("https://") {
            return Some(word.to_string());
        }
    }
    None
}

/// Normalize a Git URL for caching.
///
/// - Removes trailing slashes
/// - Removes .git suffix
/// - Keeps protocol and host
fn normalize_git_url(url: &str) -> String {
    let mut normalized = url.trim_end_matches('/').to_string();
    if normalized.ends_with(".git") {
        normalized.truncate(normalized.len() - 4);
    }
    normalized
}

/// Extract username from sudo prompt.
///
/// Looks for pattern "[sudo] password for username:"
fn extract_sudo_username(prompt: &str) -> Option<String> {
    let prompt_lower = prompt.to_lowercase();
    let marker = "password for ";
    let start = prompt_lower.find(marker)?;
    let after_marker = &prompt[start + marker.len()..];

    // Extract username (until ':' or whitespace)
    let username: String = after_marker
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ':')
        .collect();

    if !username.is_empty() {
        Some(username)
    } else {
        None
    }
}

/// Hash a string to a short hex identifier.
fn hash_string(s: &str) -> String {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    // SSH FIDO2 tests
    #[test]
    fn detect_ssh_fido_with_sha256() {
        let result = detect_cache_id("Enter PIN for ECDSA-SK key SHA256:xK3NvbHvA5N6TjXd/abc123:");
        assert_eq!(result.cache_type, CacheType::Ssh);
        assert!(result.cache_id.starts_with("ssh-fido:SHA256:"));
        assert_eq!(result.confidence, Confidence::High);
    }

    #[test]
    fn detect_ssh_fido_with_path() {
        let result = detect_cache_id("Enter PIN for ECDSA-SK key /home/user/.ssh/id_ecdsa_sk:");
        assert_eq!(result.cache_type, CacheType::Ssh);
        assert!(result.cache_id.contains(".ssh"));
        assert_eq!(result.confidence, Confidence::High);
    }

    #[test]
    fn detect_ssh_fido_ed25519() {
        let result = detect_cache_id("Enter PIN for ED25519-SK key SHA256:abcdef123456:");
        assert_eq!(result.cache_type, CacheType::Ssh);
        assert!(result.cache_id.starts_with("ssh-fido:SHA256:"));
    }

    #[test]
    fn detect_ssh_fido_generic() {
        let result = detect_cache_id("Enter PIN for key authentication");
        assert_eq!(result.cache_type, CacheType::Ssh);
        assert!(result.cache_id.starts_with("ssh-fido:"));
        assert_eq!(result.confidence, Confidence::Medium);
    }

    // Git tests
    #[test]
    fn detect_git_password_https() {
        let result = detect_cache_id("Password for 'https://github.com':");
        assert_eq!(result.cache_type, CacheType::Git);
        assert_eq!(result.cache_id, "git:https://github.com");
        assert_eq!(result.confidence, Confidence::High);
    }

    #[test]
    fn detect_git_username_https() {
        let result = detect_cache_id("Username for 'https://gitlab.com':");
        assert_eq!(result.cache_type, CacheType::Git);
        assert_eq!(result.cache_id, "git:https://gitlab.com");
    }

    #[test]
    fn detect_git_with_repo_path() {
        let result = detect_cache_id("Password for 'https://github.com/user/repo.git':");
        assert_eq!(result.cache_type, CacheType::Git);
        // Should normalize: remove .git suffix
        assert_eq!(result.cache_id, "git:https://github.com/user/repo");
    }

    #[test]
    fn detect_git_http() {
        let result = detect_cache_id("Password for 'http://git.example.com':");
        assert_eq!(result.cache_type, CacheType::Git);
        assert_eq!(result.cache_id, "git:http://git.example.com");
    }

    // Sudo tests
    #[test]
    fn detect_sudo_with_username() {
        let result = detect_cache_id("[sudo] password for robert:");
        assert_eq!(result.cache_type, CacheType::Sudo);
        assert_eq!(result.cache_id, "sudo:robert");
        assert_eq!(result.confidence, Confidence::High);
    }

    #[test]
    fn detect_sudo_uppercase() {
        let result = detect_cache_id("[SUDO] Password for admin:");
        assert_eq!(result.cache_type, CacheType::Sudo);
        assert_eq!(result.cache_id, "sudo:admin");
    }

    #[test]
    fn detect_sudo_generic_password() {
        let result = detect_cache_id("Password:");
        assert_eq!(result.cache_type, CacheType::Sudo);
        assert_eq!(result.cache_id, "sudo:generic");
        assert_eq!(result.confidence, Confidence::Low);
    }

    // Fallback tests
    #[test]
    fn detect_unknown_falls_back_to_hash() {
        let result = detect_cache_id("Enter your secret code:");
        assert_eq!(result.cache_type, CacheType::Custom);
        assert!(result.cache_id.starts_with("custom:"));
        assert_eq!(result.confidence, Confidence::Low);
    }

    #[test]
    fn detect_empty_prompt() {
        let result = detect_cache_id("");
        assert_eq!(result.cache_type, CacheType::Custom);
        assert!(result.cache_id.starts_with("custom:"));
    }

    // Hash consistency tests
    #[test]
    fn hash_is_deterministic() {
        let prompt = "Some random prompt";
        let result1 = detect_cache_id(prompt);
        let result2 = detect_cache_id(prompt);
        assert_eq!(result1.cache_id, result2.cache_id);
    }

    #[test]
    fn different_prompts_different_hashes() {
        let result1 = detect_cache_id("Prompt A");
        let result2 = detect_cache_id("Prompt B");
        assert_ne!(result1.cache_id, result2.cache_id);
    }

    // Edge cases
    #[test]
    fn prompt_with_multiple_urls() {
        // Should extract the first quoted URL
        let result = detect_cache_id("Password for 'https://github.com' or 'https://gitlab.com':");
        assert_eq!(result.cache_id, "git:https://github.com");
    }

    #[test]
    fn prompt_with_special_characters() {
        let result = detect_cache_id("[sudo] password for user-name_123:");
        assert_eq!(result.cache_id, "sudo:user-name_123");
    }

    // Helper function tests
    #[test]
    fn extract_sha256_valid() {
        assert_eq!(
            extract_sha256_fingerprint("key SHA256:abcdef123456+/="),
            Some("SHA256:abcdef123456+/=".to_string())
        );
    }

    #[test]
    fn extract_sha256_too_short() {
        assert_eq!(extract_sha256_fingerprint("key SHA256:abc"), None);
    }

    #[test]
    fn normalize_git_url_removes_trailing_slash() {
        assert_eq!(
            normalize_git_url("https://github.com/"),
            "https://github.com"
        );
    }

    #[test]
    fn normalize_git_url_removes_git_suffix() {
        assert_eq!(
            normalize_git_url("https://github.com/user/repo.git"),
            "https://github.com/user/repo"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The parser should never panic on arbitrary input.
        #[test]
        fn detect_never_panics(prompt in ".*") {
            let _ = detect_cache_id(&prompt);
        }

        /// The result should always have a non-empty cache_id.
        #[test]
        fn result_always_has_cache_id(prompt in ".*") {
            let result = detect_cache_id(&prompt);
            prop_assert!(!result.cache_id.is_empty());
        }

        /// The cache_id should be deterministic for the same input.
        #[test]
        fn detection_is_deterministic(prompt in ".*") {
            let result1 = detect_cache_id(&prompt);
            let result2 = detect_cache_id(&prompt);
            prop_assert_eq!(result1.cache_id, result2.cache_id);
            prop_assert_eq!(result1.cache_type, result2.cache_type);
            prop_assert_eq!(result1.confidence, result2.confidence);
        }

        /// SSH prompts should be detected with high or medium confidence.
        #[test]
        fn ssh_prompts_detected(
            key_type in "(ECDSA-SK|ED25519-SK|ecdsa-sk|ed25519-sk)",
            fingerprint in "[a-zA-Z0-9+/]{20,44}"
        ) {
            let prompt = format!("Enter PIN for {} key SHA256:{}:", key_type, fingerprint);
            let result = detect_cache_id(&prompt);
            prop_assert_eq!(result.cache_type, CacheType::Ssh);
            prop_assert!(result.cache_id.starts_with("ssh-fido:"));
        }

        /// Git prompts should be detected.
        #[test]
        fn git_prompts_detected(
            action in "(Password|Username)",
            host in "[a-z]{3,10}\\.[a-z]{2,4}"
        ) {
            let prompt = format!("{} for 'https://{}':", action, host);
            let result = detect_cache_id(&prompt);
            prop_assert_eq!(result.cache_type, CacheType::Git);
            prop_assert!(result.cache_id.starts_with("git:"));
        }

        /// Sudo prompts should be detected.
        #[test]
        fn sudo_prompts_detected(username in "[a-z][a-z0-9_-]{2,15}") {
            let prompt = format!("[sudo] password for {}:", username);
            let result = detect_cache_id(&prompt);
            prop_assert_eq!(result.cache_type, CacheType::Sudo);
            prop_assert_eq!(result.cache_id, format!("sudo:{}", username));
        }

        /// Unknown prompts should fall back to custom type with hash.
        #[test]
        fn unknown_prompts_fallback(prompt in "[A-Z][a-z ]{10,50}\\?") {
            // Prompts that don't match known patterns
            if !prompt.to_lowercase().contains("password")
                && !prompt.to_lowercase().contains("pin")
                && !prompt.to_lowercase().contains("https://")
            {
                let result = detect_cache_id(&prompt);
                prop_assert_eq!(result.cache_type, CacheType::Custom);
                prop_assert!(result.cache_id.starts_with("custom:"));
            }
        }
    }
}
