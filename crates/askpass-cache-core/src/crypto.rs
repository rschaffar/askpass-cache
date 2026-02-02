//! AES-256-GCM encryption for cached credentials.
//!
//! This module provides encryption primitives for protecting cached credentials
//! at rest. While the daemon already uses memory locking (`mlock`) to prevent
//! secrets from being swapped to disk, encryption adds an additional layer of
//! defense-in-depth protection.
//!
//! # Security Properties
//!
//! - **Confidentiality**: AES-256-GCM provides authenticated encryption, protecting
//!   the plaintext from exposure even if memory is somehow dumped.
//! - **Integrity**: The GCM authentication tag ensures tampering is detected.
//! - **Swap Protection**: The encryption key is stored in memory-locked (`mlock`)
//!   memory and automatically zeroed on drop.
//! - **Unique Nonces**: Each encryption operation uses a fresh random 96-bit nonce,
//!   ensuring that encrypting the same plaintext twice produces different ciphertext.
//!
//! # Example
//!
//! ```
//! use askpass_cache_core::crypto::{EncryptionKey, EncryptedSecret};
//!
//! // Generate a new random key (memory-locked)
//! let key = EncryptionKey::generate();
//!
//! // Encrypt some sensitive data
//! let plaintext = b"my-secret-password";
//! let encrypted = key.encrypt(plaintext);
//!
//! // Decrypt it back
//! let decrypted = key.decrypt(&encrypted).expect("decryption should succeed");
//! assert_eq!(decrypted, plaintext);
//! ```

use std::fmt;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;
use tracing::warn;
use zeroize::Zeroize;

/// Size of the AES-256 key in bytes.
const KEY_SIZE: usize = 32;

/// Size of the GCM nonce in bytes (96 bits).
const NONCE_SIZE: usize = 12;

/// Size of the GCM authentication tag in bytes (128 bits).
#[cfg(test)]
const TAG_SIZE: usize = 16;

/// An AES-256-GCM encryption key with secure memory handling.
///
/// The key is stored in a heap-allocated box and the memory is locked
/// using `mlock` to prevent swapping. On drop, the key is securely
/// zeroed before the memory is unlocked.
///
/// # Security
///
/// - Key material is memory-locked to prevent swapping to disk
/// - Key is automatically zeroed on drop via `Zeroize`
/// - Debug output shows `[REDACTED]` instead of key bytes
pub struct EncryptionKey {
    /// The raw 256-bit key material.
    key: Box<[u8; KEY_SIZE]>,
    /// Whether the key memory is locked.
    memory_locked: bool,
}

impl EncryptionKey {
    /// Generate a new random encryption key.
    ///
    /// The key is generated using `rand::thread_rng()` and the memory
    /// is immediately locked using `mlock`.
    ///
    /// # Panics
    ///
    /// This function does not panic, but if memory locking fails, a warning
    /// is logged and the key continues to function (though it may be swapped).
    pub fn generate() -> Self {
        let mut key = Box::new([0u8; KEY_SIZE]);
        rand::rng().fill_bytes(key.as_mut());

        let mut encryption_key = Self {
            key,
            memory_locked: false,
        };
        encryption_key.try_lock_memory();
        encryption_key
    }

    /// Attempt to lock the key memory to prevent swapping.
    fn try_lock_memory(&mut self) {
        let ptr = self.key.as_ptr() as *mut u8;
        let size = KEY_SIZE;

        // Safety: We're locking memory we own and will unlock on drop
        let result = unsafe { memsec::mlock(ptr, size) };

        if result {
            self.memory_locked = true;
        } else {
            warn!(
                "Failed to lock encryption key memory - key may be swapped to disk. \
                 Grant CAP_IPC_LOCK capability or increase RLIMIT_MEMLOCK to fix."
            );
        }
    }

    /// Encrypt plaintext data using AES-256-GCM.
    ///
    /// A fresh random 96-bit nonce is generated for each encryption operation,
    /// ensuring that encrypting the same plaintext twice produces different
    /// ciphertext.
    ///
    /// # Panics
    ///
    /// Panics if the underlying AES-GCM encryption fails (which should not
    /// happen with valid inputs).
    pub fn encrypt(&self, plaintext: &[u8]) -> EncryptedSecret {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).expect("key size is correct");

        // Generate a random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the plaintext (includes authentication tag)
        let ciphertext_with_tag = cipher
            .encrypt(nonce, plaintext)
            .expect("encryption should not fail with valid inputs");

        EncryptedSecret::from_parts(&nonce_bytes, ciphertext_with_tag)
    }

    /// Decrypt an encrypted secret using AES-256-GCM.
    ///
    /// Returns `None` if decryption fails (e.g., wrong key, corrupted data,
    /// or tampered ciphertext). A warning is logged on failure.
    ///
    /// # Security
    ///
    /// Decryption failure indicates either:
    /// - The ciphertext was encrypted with a different key
    /// - The ciphertext or authentication tag was corrupted/tampered
    ///
    /// In either case, the data should be considered untrustworthy.
    pub fn decrypt(&self, encrypted: &EncryptedSecret) -> Option<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).expect("key size is correct");

        let nonce = Nonce::from_slice(encrypted.nonce());

        match cipher.decrypt(nonce, encrypted.ciphertext_with_tag()) {
            Ok(plaintext) => Some(plaintext),
            Err(_) => {
                warn!("Decryption failed - ciphertext may be corrupted or tampered");
                None
            }
        }
    }
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        // Zeroize the key material
        self.key.zeroize();

        // Unlock memory if it was locked
        if self.memory_locked {
            let ptr = self.key.as_ptr() as *mut u8;
            let size = KEY_SIZE;
            // Safety: We're unlocking memory we previously locked
            unsafe {
                memsec::munlock(ptr, size);
            }
        }
    }
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("key", &"[REDACTED]")
            .field("memory_locked", &self.memory_locked)
            .finish()
    }
}

/// An encrypted secret with its nonce.
///
/// The internal format is: `[12-byte nonce][ciphertext][16-byte auth tag]`
///
/// This struct is designed to be stored and transmitted safely, as the
/// ciphertext reveals nothing about the plaintext without the encryption key.
#[derive(Clone)]
pub struct EncryptedSecret {
    /// The concatenated nonce, ciphertext, and authentication tag.
    data: Vec<u8>,
}

impl EncryptedSecret {
    /// Create an `EncryptedSecret` from its component parts.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The 12-byte nonce used for encryption
    /// * `ciphertext_with_tag` - The ciphertext concatenated with the 16-byte auth tag
    pub fn from_parts(nonce: &[u8], ciphertext_with_tag: Vec<u8>) -> Self {
        debug_assert_eq!(nonce.len(), NONCE_SIZE);

        let mut data = Vec::with_capacity(NONCE_SIZE + ciphertext_with_tag.len());
        data.extend_from_slice(nonce);
        data.extend(ciphertext_with_tag);

        Self { data }
    }

    /// Get the nonce portion of the encrypted data.
    pub fn nonce(&self) -> &[u8] {
        &self.data[..NONCE_SIZE]
    }

    /// Get the ciphertext and authentication tag portion.
    pub fn ciphertext_with_tag(&self) -> &[u8] {
        &self.data[NONCE_SIZE..]
    }

    /// Get the total length of the encrypted data.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the encrypted data is empty.
    ///
    /// Note: A valid `EncryptedSecret` should never be empty as it always
    /// contains at least the nonce and authentication tag.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl fmt::Debug for EncryptedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedSecret")
            .field("len", &self.data.len())
            .field("nonce_len", &NONCE_SIZE)
            .field("ciphertext_with_tag_len", &(self.data.len() - NONCE_SIZE))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = EncryptionKey::generate();
        let plaintext = b"my-super-secret-password";

        let encrypted = key.encrypt(plaintext);
        let decrypted = key.decrypt(&encrypted).expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_nonces_for_same_plaintext() {
        let key = EncryptionKey::generate();
        let plaintext = b"same-plaintext-twice";

        let encrypted1 = key.encrypt(plaintext);
        let encrypted2 = key.encrypt(plaintext);

        // Nonces should be different
        assert_ne!(encrypted1.nonce(), encrypted2.nonce());

        // Ciphertext should be different (due to different nonces)
        assert_ne!(
            encrypted1.ciphertext_with_tag(),
            encrypted2.ciphertext_with_tag()
        );

        // But both should decrypt to the same plaintext
        let decrypted1 = key
            .decrypt(&encrypted1)
            .expect("decryption 1 should succeed");
        let decrypted2 = key
            .decrypt(&encrypted2)
            .expect("decryption 2 should succeed");
        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn empty_plaintext_works() {
        let key = EncryptionKey::generate();
        let plaintext = b"";

        let encrypted = key.encrypt(plaintext);

        // Should have nonce + auth tag even for empty plaintext
        assert_eq!(encrypted.len(), NONCE_SIZE + TAG_SIZE);

        let decrypted = key.decrypt(&encrypted).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn key_debug_is_redacted() {
        let key = EncryptionKey::generate();
        let debug_output = format!("{:?}", key);

        assert!(debug_output.contains("[REDACTED]"));
        // Ensure no actual key bytes are leaked (check for typical hex patterns)
        assert!(!debug_output.contains("0x"));
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key1 = EncryptionKey::generate();
        let key2 = EncryptionKey::generate();
        let plaintext = b"secret-data";

        let encrypted = key1.encrypt(plaintext);

        // Decrypting with wrong key should fail
        assert!(key2.decrypt(&encrypted).is_none());
    }

    #[test]
    fn tampered_ciphertext_fails_decryption() {
        let key = EncryptionKey::generate();
        let plaintext = b"secret-data";

        let encrypted = key.encrypt(plaintext);

        // Tamper with the ciphertext
        let mut tampered_data = encrypted.data.clone();
        if let Some(byte) = tampered_data.get_mut(NONCE_SIZE) {
            *byte ^= 0xFF;
        }
        let tampered = EncryptedSecret {
            data: tampered_data,
        };

        // Decryption should fail due to authentication tag mismatch
        assert!(key.decrypt(&tampered).is_none());
    }

    #[test]
    fn encrypted_secret_accessors() {
        let key = EncryptionKey::generate();
        let plaintext = b"test-data";

        let encrypted = key.encrypt(plaintext);

        assert_eq!(encrypted.nonce().len(), NONCE_SIZE);
        assert!(!encrypted.is_empty());
        // Ciphertext should be plaintext length + tag size
        assert_eq!(
            encrypted.ciphertext_with_tag().len(),
            plaintext.len() + TAG_SIZE
        );
    }

    #[test]
    fn encrypted_secret_clone() {
        let key = EncryptionKey::generate();
        let plaintext = b"clone-me";

        let encrypted = key.encrypt(plaintext);
        let cloned = encrypted.clone();

        // Both should decrypt to the same plaintext
        let decrypted_original = key.decrypt(&encrypted).expect("original decryption");
        let decrypted_cloned = key.decrypt(&cloned).expect("cloned decryption");

        assert_eq!(decrypted_original, decrypted_cloned);
        assert_eq!(decrypted_original, plaintext);
    }

    #[test]
    fn encrypted_secret_debug_shows_lengths() {
        let key = EncryptionKey::generate();
        let plaintext = b"debug-test";

        let encrypted = key.encrypt(plaintext);
        let debug_output = format!("{:?}", encrypted);

        // Should show structural info, not actual data
        assert!(debug_output.contains("EncryptedSecret"));
        assert!(debug_output.contains("len"));
        assert!(debug_output.contains("nonce_len"));
    }

    #[test]
    fn large_plaintext_works() {
        let key = EncryptionKey::generate();
        let plaintext = vec![0xAB; 10_000]; // 10KB of data

        let encrypted = key.encrypt(&plaintext);
        let decrypted = key.decrypt(&encrypted).expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }
}
