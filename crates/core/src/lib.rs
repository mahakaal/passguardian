//! PassGuardian cryptographic core.
//!
//! This crate runs on the client (desktop, mobile, browser extension via WASM).
//! The server never uses it to decrypt: it only ever sees ciphertext.
//!
//! Status: skeleton (Sprint 0). Crypto, vault format, generator and TOTP arrive in Sprint 1.

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
