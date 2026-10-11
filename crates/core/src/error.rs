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
}
