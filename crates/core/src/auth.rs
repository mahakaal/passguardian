//! The login key: a secret the server can check without ever being able to decrypt anything.
//!
//! It is derived from the master key with a different label, so knowing it (or its hash,
//! which is what the server stores) gives no way back to the master key or the vault key.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;
use crate::kdf::{MasterKey, KEY_LEN};

/// Purpose label mixed into the derivation.
const AUTH_CONTEXT: &[u8] = b"passguardian/v1/auth-key";

/// The key sent to the server at registration and login. Wiped from memory when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthKey([u8; KEY_LEN]);

impl AuthKey {
    /// The raw bytes, to put on the wire.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthKey(<redacted>)")
    }
}

impl MasterKey {
    /// Derives the login key from this master key (HMAC-SHA256 with a fixed label).
    ///
    /// # Errors
    /// [`CryptoError::KeyDerivation`] if the HMAC cannot be set up, which a 32-byte key
    /// never causes.
    pub fn auth_key(&self) -> Result<AuthKey, CryptoError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.as_bytes())
            .map_err(|_| CryptoError::KeyDerivation)?;
        mac.update(AUTH_CONTEXT);
        Ok(AuthKey(mac.finalize().into_bytes().into()))
    }
}

#[cfg(test)]
mod tests {
    use crate::kdf::{derive_master_key, KdfParams};

    use super::*;

    const FAST: KdfParams = KdfParams {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    };

    fn master(password: &[u8]) -> MasterKey {
        derive_master_key(password, b"0123456789abcdef", &FAST).unwrap()
    }

    #[test]
    fn auth_key_is_deterministic() {
        assert_eq!(
            master(b"pw").auth_key().unwrap().as_bytes(),
            master(b"pw").auth_key().unwrap().as_bytes()
        );
    }

    #[test]
    fn auth_key_differs_from_the_master_key_and_between_passwords() {
        let one = master(b"one");
        assert_ne!(one.auth_key().unwrap().as_bytes(), one.as_bytes());
        assert_ne!(
            one.auth_key().unwrap().as_bytes(),
            master(b"two").auth_key().unwrap().as_bytes()
        );
    }

    #[test]
    fn auth_key_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", master(b"pw").auth_key().unwrap()),
            "AuthKey(<redacted>)"
        );
    }
}
