//! Authenticated encryption shared by key wrapping and item encryption.
//!
//! XChaCha20-Poly1305 with a fresh random 192-bit nonce per message. The nonce is large enough
//! that random generation is safe without any counter. A sealed message is
//! `nonce (24 bytes) || ciphertext || tag (16 bytes)`.
//!
//! The associated data binds a ciphertext to its context: data sealed for one purpose does not
//! open for another, even with the right key.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;

use crate::kdf::KEY_LEN;
use crate::CryptoError;

/// Length of the random nonce prepended to every sealed message, in bytes.
pub(crate) const NONCE_LEN: usize = 24;

/// Length of the Poly1305 authentication tag, in bytes.
pub(crate) const TAG_LEN: usize = 16;

/// Bytes added to the plaintext by [`seal`].
pub(crate) const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// Fills a fixed-size array with random bytes from the operating system.
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::Randomness)?;
    Ok(bytes)
}

/// Encrypts `plaintext` under `key`, binding it to `aad`.
pub(crate) fn seal(
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Encryption)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encryption)?;

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Decrypts a message produced by [`seal`]. The result is wiped from memory when dropped.
pub(crate) fn open(
    key: &[u8; KEY_LEN],
    sealed: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if sealed.len() < OVERHEAD {
        return Err(CryptoError::MalformedCiphertext);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Decryption)?;
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [7; KEY_LEN];

    #[test]
    fn seal_open_roundtrip() {
        let sealed = seal(&KEY, b"secret", b"ctx").unwrap();
        assert_eq!(sealed.len(), b"secret".len() + OVERHEAD);
        assert_eq!(&**open(&KEY, &sealed, b"ctx").unwrap(), b"secret");
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let sealed = seal(&KEY, b"", b"").unwrap();
        assert_eq!(sealed.len(), OVERHEAD);
        assert!(open(&KEY, &sealed, b"").unwrap().is_empty());
    }

    #[test]
    fn wrong_key_or_wrong_context_is_rejected() {
        let sealed = seal(&KEY, b"secret", b"ctx").unwrap();
        assert_eq!(
            open(&[8; KEY_LEN], &sealed, b"ctx").unwrap_err(),
            CryptoError::Decryption
        );
        assert_eq!(
            open(&KEY, &sealed, b"other").unwrap_err(),
            CryptoError::Decryption
        );
    }

    #[test]
    fn too_short_input_is_malformed_not_a_panic() {
        for len in 0..OVERHEAD {
            assert_eq!(
                open(&KEY, &vec![0u8; len], b"").unwrap_err(),
                CryptoError::MalformedCiphertext
            );
        }
    }

    #[test]
    fn nonce_is_never_reused() {
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let sealed = seal(&KEY, b"same plaintext", b"").unwrap();
            assert!(nonces.insert(sealed[..NONCE_LEN].to_vec()), "nonce reused");
        }
    }
}
