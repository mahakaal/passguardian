//! PassGuardian cryptographic core.
//!
//! This crate runs on the client (desktop, mobile, browser extension via WASM).
//! The server never uses it to decrypt: it only ever sees ciphertext.
//!
//! Status: Sprint 1 in progress. Key derivation is in place; vault key wrapping, item
//! encryption, vault format, generator and TOTP follow.

mod aead;
pub mod error;
pub mod item;
pub mod kdf;
pub mod vault_key;

pub use error::CryptoError;
pub use item::{decrypt_item, encrypt_item, EncryptedItem};
pub use kdf::{derive_master_key, KdfParams, MasterKey};
pub use vault_key::{VaultKey, WrappedVaultKey};

/// Version of the serialized vault format.
///
/// Every incompatible change increments this number and requires a migration.
pub const VAULT_FORMAT_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_format_version_is_set() {
        assert_eq!(VAULT_FORMAT_VERSION, 1);
    }
}
