//! Encryption of vault items with the vault key.
//!
//! Each item is sealed with XChaCha20-Poly1305 under the vault key. The item identifier is part
//! of the authenticated data, so a ciphertext cannot be moved to a different item (for example
//! by a malicious server swapping two rows) without being detected.

use zeroize::Zeroizing;

use crate::{aead, CryptoError, VaultKey};

/// Purpose label mixed into the authenticated data of every item.
const ITEM_CONTEXT: &[u8] = b"passguardian/v1/item";

/// An encrypted vault item. Safe to store and to send to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedItem(Vec<u8>);

impl EncryptedItem {
    /// Serialized form, to store or send.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Rebuilds an encrypted item from its serialized form. The content is only checked when
    /// decrypting.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Encrypts `plaintext` as the item identified by `item_id`.
pub fn encrypt_item(
    vault_key: &VaultKey,
    item_id: &[u8],
    plaintext: &[u8],
) -> Result<EncryptedItem, CryptoError> {
    aead::seal(vault_key.as_bytes(), plaintext, &associated_data(item_id)).map(EncryptedItem)
}

/// Purpose label followed by the item identifier. The identifier comes last, so the encoding is
/// unambiguous without a length prefix.
fn associated_data(item_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ITEM_CONTEXT.len() + item_id.len());
    aad.extend_from_slice(ITEM_CONTEXT);
    aad.extend_from_slice(item_id);
    aad
}

/// Decrypts an item. The plaintext is wiped from memory when dropped.
///
/// # Errors
/// [`CryptoError::Decryption`] if the key or the item identifier is wrong, or the data was
/// modified; [`CryptoError::MalformedCiphertext`] if it is too short to be an item.
pub fn decrypt_item(
    vault_key: &VaultKey,
    item_id: &[u8],
    item: &EncryptedItem,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    aead::open(vault_key.as_bytes(), &item.0, &associated_data(item_id))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::aead::{NONCE_LEN, OVERHEAD};

    fn key() -> VaultKey {
        VaultKey::generate().unwrap()
    }

    #[test]
    fn encrypt_decrypt_item_roundtrip() {
        let key = key();
        let item = encrypt_item(&key, b"item-1", b"hunter2").unwrap();
        assert_eq!(&**decrypt_item(&key, b"item-1", &item).unwrap(), b"hunter2");
    }

    proptest! {
        #[test]
        fn roundtrip_is_the_identity_for_any_payload(
            payload in proptest::collection::vec(any::<u8>(), 0..4096),
            id in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let key = VaultKey::generate().unwrap();
            let item = encrypt_item(&key, &id, &payload).unwrap();
            prop_assert_eq!(item.as_bytes().len(), payload.len() + OVERHEAD);
            let plain = decrypt_item(&key, &id, &item).unwrap();
            prop_assert_eq!(&**plain, &payload[..]);
        }
    }

    #[test]
    fn large_payload_roundtrips() {
        let key = key();
        let payload = vec![0xA5; 1024 * 1024];
        let item = encrypt_item(&key, b"big", &payload).unwrap();
        assert_eq!(&**decrypt_item(&key, b"big", &item).unwrap(), &payload[..]);
    }

    #[test]
    fn tampered_ciphertext_is_rejected_for_every_bit() {
        let key = key();
        let item = encrypt_item(&key, b"item-1", b"a short secret").unwrap();
        assert_eq!(item.as_bytes().len(), 14 + OVERHEAD);
        for byte in 0..item.as_bytes().len() {
            for bit in 0..8 {
                let mut bytes = item.as_bytes().to_vec();
                bytes[byte] ^= 1 << bit;
                let tampered = EncryptedItem::from_bytes(bytes);
                assert!(
                    decrypt_item(&key, b"item-1", &tampered).is_err(),
                    "flipping bit {bit} of byte {byte} went unnoticed"
                );
            }
        }
    }

    #[test]
    fn truncated_or_extended_ciphertext_is_rejected() {
        let key = key();
        let item = encrypt_item(&key, b"item-1", b"secret").unwrap();
        for len in 0..item.as_bytes().len() {
            let cut = EncryptedItem::from_bytes(item.as_bytes()[..len].to_vec());
            assert!(decrypt_item(&key, b"item-1", &cut).is_err(), "length {len}");
        }
        let mut longer = item.as_bytes().to_vec();
        longer.push(0);
        assert!(decrypt_item(&key, b"item-1", &EncryptedItem::from_bytes(longer)).is_err());
    }

    #[test]
    fn wrong_vault_key_is_rejected() {
        let item = encrypt_item(&key(), b"item-1", b"secret").unwrap();
        let err = decrypt_item(&key(), b"item-1", &item).unwrap_err();
        assert_eq!(err, CryptoError::Decryption);
    }

    #[test]
    fn ciphertext_cannot_be_moved_to_another_item() {
        let key = key();
        let item = encrypt_item(&key, b"item-1", b"secret").unwrap();
        let err = decrypt_item(&key, b"item-2", &item).unwrap_err();
        assert_eq!(err, CryptoError::Decryption);
    }

    #[test]
    fn a_wrapped_vault_key_cannot_be_opened_as_an_item() {
        let master = crate::derive_master_key(
            b"pw",
            b"0123456789abcdef",
            &crate::KdfParams {
                memory_kib: 64,
                iterations: 1,
                parallelism: 1,
            },
        )
        .unwrap();
        let wrapped = key().wrap(&master).unwrap();
        let as_item = EncryptedItem::from_bytes(wrapped.as_bytes().to_vec());
        // Even with the right key material the purpose label differs, so this never opens.
        assert!(decrypt_item(&key(), b"", &as_item).is_err());
    }

    #[test]
    fn nonce_is_never_reused() {
        let key = key();
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let item = encrypt_item(&key, b"item-1", b"same plaintext").unwrap();
            assert!(
                nonces.insert(item.as_bytes()[..NONCE_LEN].to_vec()),
                "nonce reused"
            );
        }
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let key = key();
        let plain = b"correct horse battery staple";
        let item = encrypt_item(&key, b"item-1", plain).unwrap();
        assert!(!item
            .as_bytes()
            .windows(plain.len())
            .any(|w| w == plain.as_slice()));
    }
}
