//! The random vault key and its wrapping with the master key.
//!
//! The vault key encrypts every item. It is random and never derived from the password, so a
//! password change only re-wraps this key instead of re-encrypting the whole vault.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::kdf::KEY_LEN;
use crate::{aead, CryptoError, MasterKey};

/// Associated data that ties a wrapped key to its purpose, so it cannot be replayed as an item.
const WRAP_CONTEXT: &[u8] = b"passguardian/v1/vault-key";

/// The random 256-bit key that encrypts the vault items. Wiped from memory when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; KEY_LEN]);

/// The vault key encrypted with the master key. Safe to store and to send to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedVaultKey(Vec<u8>);

impl VaultKey {
    /// Generates a new random vault key.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(aead::random_bytes()?))
    }

    /// Raw key bytes. Handle with care: do not copy, log or persist them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Encrypts this key with the master key.
    pub fn wrap(&self, master: &MasterKey) -> Result<WrappedVaultKey, CryptoError> {
        aead::seal(master.as_bytes(), &self.0, WRAP_CONTEXT).map(WrappedVaultKey)
    }

    /// Decrypts a wrapped vault key.
    ///
    /// # Errors
    /// [`CryptoError::Decryption`] if the master key is wrong or the data was modified.
    pub fn unwrap(wrapped: &WrappedVaultKey, master: &MasterKey) -> Result<Self, CryptoError> {
        let plain = aead::open(master.as_bytes(), &wrapped.0, WRAP_CONTEXT)?;
        let bytes: [u8; KEY_LEN] = plain
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::MalformedCiphertext)?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey(<redacted>)")
    }
}

impl WrappedVaultKey {
    /// Serialized form, to store or send.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Rebuilds a wrapped key from its serialized form. The content is only checked when
    /// unwrapping.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{derive_master_key, KdfParams};

    const FAST: KdfParams = KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    fn master(password: &[u8]) -> MasterKey {
        derive_master_key(password, b"0123456789abcdef", &FAST).unwrap()
    }

    #[test]
    fn generated_vault_keys_are_distinct_and_not_zero() {
        let a = VaultKey::generate().unwrap();
        let b = VaultKey::generate().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), &[0u8; KEY_LEN]);
    }

    #[test]
    fn wrap_unwrap_vault_key_roundtrip() {
        let master = master(b"hunter2");
        let vault_key = VaultKey::generate().unwrap();
        let wrapped = vault_key.wrap(&master).unwrap();
        let unwrapped = VaultKey::unwrap(&wrapped, &master).unwrap();
        assert_eq!(unwrapped.as_bytes(), vault_key.as_bytes());
    }

    #[test]
    fn unwrap_with_wrong_master_key_fails() {
        let vault_key = VaultKey::generate().unwrap();
        let wrapped = vault_key.wrap(&master(b"right")).unwrap();
        let err = VaultKey::unwrap(&wrapped, &master(b"wrong")).unwrap_err();
        assert_eq!(err, CryptoError::Decryption);
    }

    #[test]
    fn wrapped_key_has_the_expected_length() {
        let wrapped = VaultKey::generate().unwrap().wrap(&master(b"x")).unwrap();
        assert_eq!(wrapped.as_bytes().len(), KEY_LEN + aead::OVERHEAD);
    }

    #[test]
    fn wrapped_key_does_not_contain_the_plain_key() {
        let master = master(b"hunter2");
        let vault_key = VaultKey::generate().unwrap();
        let wrapped = vault_key.wrap(&master).unwrap();
        let plain = vault_key.as_bytes();
        assert!(!wrapped.as_bytes().windows(KEY_LEN).any(|w| w == plain));
    }

    #[test]
    fn wrapping_twice_gives_different_output() {
        let master = master(b"hunter2");
        let vault_key = VaultKey::generate().unwrap();
        let a = vault_key.wrap(&master).unwrap();
        let b = vault_key.wrap(&master).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn tampered_wrapped_key_is_rejected_for_every_bit() {
        let master = master(b"hunter2");
        let wrapped = VaultKey::generate().unwrap().wrap(&master).unwrap();
        for byte in 0..wrapped.as_bytes().len() {
            for bit in 0..8 {
                let mut bytes = wrapped.as_bytes().to_vec();
                bytes[byte] ^= 1 << bit;
                let tampered = WrappedVaultKey::from_bytes(bytes);
                assert!(
                    VaultKey::unwrap(&tampered, &master).is_err(),
                    "flipping bit {bit} of byte {byte} went unnoticed"
                );
            }
        }
    }

    #[test]
    fn truncated_wrapped_key_is_rejected() {
        let master = master(b"hunter2");
        let wrapped = VaultKey::generate().unwrap().wrap(&master).unwrap();
        for len in [0, 1, 23, 24, wrapped.as_bytes().len() - 1] {
            let cut = WrappedVaultKey::from_bytes(wrapped.as_bytes()[..len].to_vec());
            assert!(VaultKey::unwrap(&cut, &master).is_err(), "length {len}");
        }
    }

    #[test]
    fn debug_output_does_not_leak_the_key() {
        let vault_key = VaultKey::generate().unwrap();
        assert_eq!(format!("{vault_key:?}"), "VaultKey(<redacted>)");
    }
}
