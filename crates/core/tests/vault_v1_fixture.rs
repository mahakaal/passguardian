//! Compatibility guard: a vault written in format version 1 must open with every future build.
//!
//! `fixtures/vault-v1.json` is frozen. If this test fails, the format or the cryptography changed
//! in an incompatible way: bump `VAULT_FORMAT_VERSION` and add a migration, do not edit the file.

use passguardian_core::{
    decrypt_item, derive_master_key, CryptoError, VaultDocument, VaultKey, VAULT_FORMAT_VERSION,
};

const FIXTURE: &str = include_str!("fixtures/vault-v1.json");
const PASSWORD: &[u8] = b"correct horse battery staple";

#[test]
fn frozen_v1_vault_still_loads_and_decrypts() {
    let doc = VaultDocument::from_json(FIXTURE).unwrap();
    assert_eq!(doc.version, 1);
    assert!(doc.version <= VAULT_FORMAT_VERSION);

    let master = derive_master_key(PASSWORD, &doc.salt, &doc.kdf).unwrap();
    let vault_key = VaultKey::unwrap(&doc.wrapped_vault_key, &master).unwrap();

    let expected: [(&str, &[u8]); 2] = [
        (
            "login-github",
            br#"{"name":"GitHub","username":"manu","password":"hunter2"}"#,
        ),
        ("note-1", b"a secure note"),
    ];
    assert_eq!(doc.items.len(), expected.len());
    for (record, (id, plain)) in doc.items.iter().zip(expected) {
        assert_eq!(record.id, id);
        let decrypted = decrypt_item(&vault_key, record.id.as_bytes(), &record.item).unwrap();
        assert_eq!(&**decrypted, plain);
    }
}

#[test]
fn frozen_v1_vault_does_not_open_with_the_wrong_password() {
    let doc = VaultDocument::from_json(FIXTURE).unwrap();
    let master = derive_master_key(b"wrong password", &doc.salt, &doc.kdf).unwrap();
    let err = VaultKey::unwrap(&doc.wrapped_vault_key, &master).unwrap_err();
    assert_eq!(err, CryptoError::Decryption);
}

#[test]
fn frozen_v1_vault_survives_a_write_and_read_cycle() {
    let doc = VaultDocument::from_json(FIXTURE).unwrap();
    assert_eq!(
        VaultDocument::from_json(&doc.to_json().unwrap()).unwrap(),
        doc
    );
}
