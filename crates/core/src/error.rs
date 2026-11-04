//! Errors returned by the cryptographic core.
//!
//! Variants never carry secret material, so they are safe to log.

use thiserror::Error;

/// Everything that can go wrong in `passguardian-core`.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// The salt is shorter than the minimum accepted length.
    #[error("salt must be at least {min} bytes")]
    SaltTooShort {
        /// Minimum accepted salt length, in bytes.
        min: usize,
    },
    /// The key-derivation parameters are not acceptable.
    #[error("invalid key derivation parameters")]
    InvalidKdfParams,
    /// The key derivation itself failed.
    #[error("key derivation failed")]
    KeyDerivation,
    /// The operating system could not provide random bytes.
    #[error("random number generator unavailable")]
    Randomness,
    /// Encryption failed.
    #[error("encryption failed")]
    Encryption,
    /// The data is too short or not shaped like ciphertext produced by this crate.
    #[error("malformed ciphertext")]
    MalformedCiphertext,
    /// Authentication failed: wrong key, wrong context, or the data was modified.
    ///
    /// Deliberately carries no detail about which of those it was.
    #[error("decryption failed")]
    Decryption,
}
