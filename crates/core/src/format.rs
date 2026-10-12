//! The serialized, versioned vault document.
//!
//! A vault travels as JSON: it can be exported, imported and synchronized. Everything secret in
//! it is already ciphertext; the document only adds the parameters needed to open it.
//!
//! Every document carries a `version`. Loading rules:
//! - a version newer than this build understands is rejected, never guessed at;
//! - an older version is migrated step by step (`n` → `n + 1`) up to the current one;
//! - unknown fields are rejected, so a typo or a downgrade cannot silently drop data.
//!
//! Layout of version 1:
//! ```json
//! {
//!   "version": 1,
//!   "kdf": { "memory_kib": 65536, "iterations": 3, "parallelism": 4 },
//!   "salt": "<base64>",
//!   "wrapped_vault_key": "<base64>",
//!   "items": [ { "id": "<text>", "data": "<base64>" } ]
//! }
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{EncryptedItem, KdfParams, WrappedVaultKey, VAULT_FORMAT_VERSION};

/// Errors raised while reading or writing a vault document.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormatError {
    /// Not valid JSON, not shaped like a vault, or a field has the wrong type.
    #[error("malformed vault document")]
    Malformed,
    /// The document was written by a newer version of PassGuardian (or has no valid version).
    #[error("unsupported vault format version {found} (this build supports up to {supported})")]
    UnsupportedVersion {
        /// Version found in the document.
        found: u64,
        /// Newest version this build can read.
        supported: u32,
    },
    /// A migration step failed or is missing, so the document could not be brought up to date.
    #[error("could not migrate the vault from format version {from}")]
    MigrationFailed {
        /// Version the failing step was migrating from.
        from: u32,
    },
}

/// One encrypted item with its identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRecord {
    /// Item identifier. It is bound to the ciphertext, see [`crate::encrypt_item`].
    pub id: String,
    /// The encrypted item.
    pub item: EncryptedItem,
}

/// A whole vault, ready to be written or just read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultDocument {
    /// Format version of this document.
    pub version: u32,
    /// Parameters used to derive the master key from the master password.
    pub kdf: KdfParams,
    /// Salt used with the master password.
    pub salt: Vec<u8>,
    /// The vault key, encrypted with the master key.
    pub wrapped_vault_key: WrappedVaultKey,
    /// The encrypted items.
    pub items: Vec<VaultRecord>,
}

/// A migration step: rewrites a document of version `n` into one of version `n + 1`.
type Migration = fn(Value) -> Result<Value, FormatError>;

/// Steps from older versions. `MIGRATIONS[i]` takes version `i + 1` to `i + 2`.
/// Empty while version 1 is the only one that has ever existed.
const MIGRATIONS: &[Migration] = &[];

impl VaultDocument {
    /// Builds a document in the current format.
    #[must_use]
    pub fn new(
        kdf: KdfParams,
        salt: Vec<u8>,
        wrapped_vault_key: WrappedVaultKey,
        items: Vec<VaultRecord>,
    ) -> Self {
        Self {
            version: VAULT_FORMAT_VERSION,
            kdf,
            salt,
            wrapped_vault_key,
            items,
        }
    }

    /// Serializes the document to JSON.
    pub fn to_json(&self) -> Result<String, FormatError> {
        serde_json::to_string_pretty(&Wire::from(self)).map_err(|_| FormatError::Malformed)
    }

    /// Reads a document, migrating it to the current format if it is older.
    ///
    /// # Errors
    /// See [`FormatError`].
    pub fn from_json(json: &str) -> Result<Self, FormatError> {
        parse(json, VAULT_FORMAT_VERSION, MIGRATIONS)
    }
}

/// Reads `json`, migrating it with `migrations` until it reaches version `current`.
fn parse(json: &str, current: u32, migrations: &[Migration]) -> Result<VaultDocument, FormatError> {
    let mut value: Value = serde_json::from_str(json).map_err(|_| FormatError::Malformed)?;
    let found = value
        .get("version")
        .and_then(Value::as_u64)
        .ok_or(FormatError::Malformed)?;
    if found == 0 || found > u64::from(current) {
        return Err(FormatError::UnsupportedVersion {
            found,
            supported: current,
        });
    }
    let mut version = u32::try_from(found).map_err(|_| FormatError::Malformed)?;

    while version < current {
        let failed = FormatError::MigrationFailed { from: version };
        let step = migrations
            .get(usize::try_from(version - 1).map_err(|_| FormatError::Malformed)?)
            .ok_or(failed)?;
        value = step(value).map_err(|_| FormatError::MigrationFailed { from: version })?;
        // A step that forgets to bump the version would loop on the same document forever.
        if value.get("version").and_then(Value::as_u64) != Some(u64::from(version) + 1) {
            return Err(FormatError::MigrationFailed { from: version });
        }
        version += 1;
    }

    let wire: Wire = serde_json::from_value(value).map_err(|_| FormatError::Malformed)?;
    Ok(wire.into())
}

// --- Wire representation -------------------------------------------------------------------
// Kept private so that serde, and the exact JSON shape, are not part of the public API.

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u32,
    kdf: WireKdf,
    #[serde(with = "b64")]
    salt: Vec<u8>,
    #[serde(with = "b64")]
    wrapped_vault_key: Vec<u8>,
    items: Vec<WireRecord>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireKdf {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRecord {
    id: String,
    #[serde(with = "b64")]
    data: Vec<u8>,
}

impl From<&VaultDocument> for Wire {
    fn from(doc: &VaultDocument) -> Self {
        Self {
            version: doc.version,
            kdf: WireKdf {
                memory_kib: doc.kdf.memory_kib,
                iterations: doc.kdf.iterations,
                parallelism: doc.kdf.parallelism,
            },
            salt: doc.salt.clone(),
            wrapped_vault_key: doc.wrapped_vault_key.as_bytes().to_vec(),
            items: doc
                .items
                .iter()
                .map(|record| WireRecord {
                    id: record.id.clone(),
                    data: record.item.as_bytes().to_vec(),
                })
                .collect(),
        }
    }
}

impl From<Wire> for VaultDocument {
    fn from(wire: Wire) -> Self {
        Self {
            version: wire.version,
            kdf: KdfParams {
                memory_kib: wire.kdf.memory_kib,
                iterations: wire.kdf.iterations,
                parallelism: wire.kdf.parallelism,
            },
            salt: wire.salt,
            wrapped_vault_key: WrappedVaultKey::from_bytes(wire.wrapped_vault_key),
            items: wire
                .items
                .into_iter()
                .map(|record| VaultRecord {
                    id: record.id,
                    item: EncryptedItem::from_bytes(record.data),
                })
                .collect(),
        }
    }
}

/// Serde adapter: bytes as standard base64 text.
mod b64 {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD.decode(text).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn sample() -> VaultDocument {
        VaultDocument::new(
            KdfParams {
                memory_kib: 64,
                iterations: 2,
                parallelism: 1,
            },
            vec![1; 16],
            WrappedVaultKey::from_bytes(vec![2; 72]),
            vec![
                VaultRecord {
                    id: "item-1".into(),
                    item: EncryptedItem::from_bytes(vec![3; 40]),
                },
                VaultRecord {
                    id: "item-2".into(),
                    item: EncryptedItem::from_bytes(vec![4; 41]),
                },
            ],
        )
    }

    fn v1_json() -> Value {
        serde_json::from_str(&sample().to_json().unwrap()).unwrap()
    }

    #[test]
    fn document_roundtrips_through_json() {
        let doc = sample();
        let back = VaultDocument::from_json(&doc.to_json().unwrap()).unwrap();
        assert_eq!(back, doc);
        assert_eq!(back.version, VAULT_FORMAT_VERSION);
    }

    #[test]
    fn serialized_document_declares_its_version_and_hides_nothing_in_clear() {
        let json = v1_json();
        assert_eq!(json["version"], json!(VAULT_FORMAT_VERSION));
        assert_eq!(json["items"][0]["id"], json!("item-1"));
        assert!(json["salt"].is_string() && json["wrapped_vault_key"].is_string());
    }

    #[test]
    fn unknown_format_version_is_rejected() {
        for version in [json!(VAULT_FORMAT_VERSION + 1), json!(999), json!(u64::MAX)] {
            let mut doc = v1_json();
            doc["version"] = version.clone();
            let err = VaultDocument::from_json(&doc.to_string()).unwrap_err();
            assert_eq!(
                err,
                FormatError::UnsupportedVersion {
                    found: version.as_u64().unwrap(),
                    supported: VAULT_FORMAT_VERSION
                }
            );
        }
    }

    #[test]
    fn version_zero_missing_or_not_a_number_is_rejected() {
        let mut doc = v1_json();
        doc["version"] = json!(0);
        assert_eq!(
            VaultDocument::from_json(&doc.to_string()).unwrap_err(),
            FormatError::UnsupportedVersion {
                found: 0,
                supported: VAULT_FORMAT_VERSION
            }
        );
        for bad in [json!("1"), json!(1.5), json!(-1), json!(null)] {
            let mut doc = v1_json();
            doc["version"] = bad;
            assert_eq!(
                VaultDocument::from_json(&doc.to_string()).unwrap_err(),
                FormatError::Malformed
            );
        }
        let mut doc = v1_json();
        doc.as_object_mut().unwrap().remove("version");
        assert_eq!(
            VaultDocument::from_json(&doc.to_string()).unwrap_err(),
            FormatError::Malformed
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut doc = v1_json();
        doc["surprise"] = json!(true);
        assert_eq!(
            VaultDocument::from_json(&doc.to_string()).unwrap_err(),
            FormatError::Malformed
        );
    }

    #[test]
    fn malformed_documents_are_rejected() {
        for bad in ["", "not json", "[]", "{}", "null"] {
            assert_eq!(
                VaultDocument::from_json(bad).unwrap_err(),
                FormatError::Malformed,
                "{bad:?}"
            );
        }
        let mut doc = v1_json();
        doc["salt"] = json!("!!! not base64 !!!");
        assert_eq!(
            VaultDocument::from_json(&doc.to_string()).unwrap_err(),
            FormatError::Malformed
        );
    }

    // --- Migration engine -------------------------------------------------------------------
    // No real migration exists yet (version 1 is the first format), so the engine is tested with
    // a synthetic history: version 1 called its wrapped key `wrapped_key` and kept no `kdf` block
    // name changes; version 2 renames it; version 3 only bumps the number.

    fn v1_to_v2(mut doc: Value) -> Result<Value, FormatError> {
        let obj = doc
            .as_object_mut()
            .ok_or(FormatError::MigrationFailed { from: 1 })?;
        let key = obj
            .remove("wrapped_key")
            .ok_or(FormatError::MigrationFailed { from: 1 })?;
        obj.insert("wrapped_vault_key".into(), key);
        obj.insert("version".into(), json!(2));
        Ok(doc)
    }

    #[allow(clippy::unnecessary_wraps)] // must match the `Migration` signature
    fn v2_to_v3(mut doc: Value) -> Result<Value, FormatError> {
        doc["version"] = json!(3);
        Ok(doc)
    }

    fn legacy_json() -> String {
        let mut doc = v1_json();
        let obj = doc.as_object_mut().unwrap();
        let key = obj.remove("wrapped_vault_key").unwrap();
        obj.insert("wrapped_key".into(), key);
        obj.insert("version".into(), json!(1));
        doc.to_string()
    }

    #[test]
    fn old_format_version_is_migrated() {
        let migrated = parse(&legacy_json(), 3, &[v1_to_v2, v2_to_v3]).unwrap();
        assert_eq!(migrated.version, 3);
        assert_eq!(migrated.wrapped_vault_key, sample().wrapped_vault_key);
        assert_eq!(migrated.items, sample().items);
    }

    #[test]
    fn a_document_already_current_is_not_touched_by_migrations() {
        let mut doc = v1_json();
        doc["version"] = json!(3);
        let loaded = parse(&doc.to_string(), 3, &[v1_to_v2, v2_to_v3]).unwrap();
        assert_eq!(loaded.version, 3);
    }

    #[test]
    fn missing_migration_step_is_an_error_not_a_guess() {
        // Current is 3 but only the 1 → 2 step exists: a version-2 document cannot be upgraded.
        let mut doc = v1_json();
        doc["version"] = json!(2);
        let err = parse(&doc.to_string(), 3, &[v1_to_v2]).unwrap_err();
        assert_eq!(err, FormatError::MigrationFailed { from: 2 });
    }

    #[test]
    fn failing_migration_step_is_reported_with_its_version() {
        // A version-1 document without `wrapped_key` makes the first step fail.
        let err = parse(&v1_json().to_string(), 3, &[v1_to_v2, v2_to_v3]).unwrap_err();
        assert_eq!(err, FormatError::MigrationFailed { from: 1 });
    }

    #[test]
    fn migration_must_actually_advance_the_version() {
        #[allow(clippy::unnecessary_wraps)] // must match the `Migration` signature
        fn lazy(doc: Value) -> Result<Value, FormatError> {
            Ok(doc) // forgets to bump `version`
        }
        let err = parse(&legacy_json(), 2, &[lazy]).unwrap_err();
        assert_eq!(err, FormatError::MigrationFailed { from: 1 });
    }
}
