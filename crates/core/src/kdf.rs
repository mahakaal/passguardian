//! Master key derivation: master password → Argon2id → master key.
//!
//! The master key never leaves the client. It only wraps the random vault key (Sprint 1, S1-2).

use std::fmt;

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoError;

/// Length of the derived master key, in bytes (256 bit).
pub const KEY_LEN: usize = 32;

/// Shortest salt accepted by [`derive_master_key`], in bytes.
pub const MIN_SALT_LEN: usize = 16;

/// Argon2id cost parameters. Stored next to the vault so they can be raised later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost, in KiB.
    pub memory_kib: u32,
    /// Number of passes over the memory.
    pub iterations: u32,
    /// Degree of parallelism (lanes).
    pub parallelism: u32,
}

impl KdfParams {
    /// Provisional defaults (64 MiB, 3 passes, 4 lanes). The final values are fixed by the
    /// Sprint 1 ADR (S1-7).
    pub const DEFAULT: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 4,
    };
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The key derived from the master password. Wiped from memory when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    /// Raw key bytes. Handle with care: do not copy, log or persist them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

/// Derives the master key from the master password with Argon2id (version 0x13).
///
/// # Errors
/// [`CryptoError::SaltTooShort`] if the salt is under [`MIN_SALT_LEN`] bytes,
/// [`CryptoError::InvalidKdfParams`] if the parameters are rejected.
pub fn derive_master_key(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<MasterKey, CryptoError> {
    if salt.len() < MIN_SALT_LEN {
        return Err(CryptoError::SaltTooShort { min: MIN_SALT_LEN });
    }
    derive(password, salt, params, None, &[])
}

/// Argon2id with the optional secret and associated data of RFC 9106. The public API leaves
/// both empty; they exist so the RFC test vector can exercise the whole algorithm.
fn derive(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
    secret: Option<&[u8]>,
    associated_data: &[u8],
) -> Result<MasterKey, CryptoError> {
    let argon_params = ParamsBuilder::new()
        .m_cost(params.memory_kib)
        .t_cost(params.iterations)
        .p_cost(params.parallelism)
        .output_len(KEY_LEN)
        .data(AssociatedData::new(associated_data).map_err(|_| CryptoError::InvalidKdfParams)?)
        .build()
        .map_err(|_| CryptoError::InvalidKdfParams)?;

    let argon = match secret {
        Some(secret) => {
            Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, argon_params)
                .map_err(|_| CryptoError::InvalidKdfParams)?
        }
        None => Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params),
    };

    let mut key = MasterKey([0; KEY_LEN]);
    argon
        .hash_password_into(password, salt, &mut key.0)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap parameters so tests stay fast: 64 KiB, 2 passes, 1 lane.
    const FAST: KdfParams = KdfParams {
        memory_kib: 64,
        iterations: 2,
        parallelism: 1,
    };
    const SALT: &[u8] = b"0123456789abcdef";
    const PASSWORD: &[u8] = b"correct horse battery staple";

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    /// RFC 9106, section 5.3: official Argon2id test vector (uses a secret and associated data).
    #[test]
    fn rfc9106_argon2id_vector() {
        let params = KdfParams {
            memory_kib: 32,
            iterations: 3,
            parallelism: 4,
        };
        let key = derive(
            &[0x01; 32],
            &[0x02; 16],
            &params,
            Some(&[0x03; 8]),
            &[0x04; 12],
        )
        .unwrap();
        assert_eq!(
            hex(key.as_bytes()),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    // The next two vectors were produced with libargon2 (argon2-cffi), an implementation
    // independent from the RustCrypto crate used here.
    #[test]
    fn argon2id_derive_matches_known_vector() {
        let key = derive_master_key(PASSWORD, SALT, &FAST).unwrap();
        assert_eq!(
            hex(key.as_bytes()),
            "800c095b9bf1e62b67d95f4a1e51148f2502ae90d880ac907f480c6871b1d61e"
        );
    }

    #[test]
    fn argon2id_derive_matches_known_vector_with_parallelism() {
        let params = KdfParams {
            memory_kib: 256,
            iterations: 3,
            parallelism: 4,
        };
        let key = derive_master_key(PASSWORD, SALT, &params).unwrap();
        assert_eq!(
            hex(key.as_bytes()),
            "4c12c52d3a08230e3827d039f19013c61b669d945b1a3a794f64941d65ce7540"
        );
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = derive_master_key(PASSWORD, SALT, &FAST).unwrap();
        let b = derive_master_key(PASSWORD, SALT, &FAST).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_password_gives_different_key() {
        let a = derive_master_key(b"one", SALT, &FAST).unwrap();
        let b = derive_master_key(b"two", SALT, &FAST).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_salt_gives_different_key() {
        let a = derive_master_key(PASSWORD, b"0123456789abcdef", &FAST).unwrap();
        let b = derive_master_key(PASSWORD, b"fedcba9876543210", &FAST).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn short_salt_is_rejected() {
        let err = derive_master_key(PASSWORD, &SALT[..MIN_SALT_LEN - 1], &FAST).unwrap_err();
        assert_eq!(err, CryptoError::SaltTooShort { min: MIN_SALT_LEN });
    }

    #[test]
    fn invalid_params_are_rejected() {
        for params in [
            KdfParams {
                memory_kib: 0,
                ..FAST
            },
            KdfParams {
                iterations: 0,
                ..FAST
            },
            KdfParams {
                parallelism: 0,
                ..FAST
            },
            // Memory must be at least 8 KiB per lane.
            KdfParams {
                memory_kib: 8,
                parallelism: 2,
                ..FAST
            },
        ] {
            assert_eq!(
                derive_master_key(PASSWORD, SALT, &params).unwrap_err(),
                CryptoError::InvalidKdfParams,
                "{params:?}"
            );
        }
    }

    #[test]
    fn debug_output_does_not_leak_the_key() {
        let key = derive_master_key(PASSWORD, SALT, &FAST).unwrap();
        let shown = format!("{key:?}");
        assert!(!shown.contains(&hex(key.as_bytes())));
        assert_eq!(shown, "MasterKey(<redacted>)");
    }
}
