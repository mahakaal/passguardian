//! Domain entities. Plain data plus the rules that keep it consistent; no I/O.
//!
//! The server only ever sees ciphertext: `Cipher::data` and `Folder::name` are opaque bytes
//! produced by the client (ADR 0003). The domain never interprets them.

use crate::{CipherId, DeviceId, DomainError, Email, FolderId, Revision, UserId};

/// Longest device name accepted, in characters.
pub const MAX_DEVICE_NAME_LEN: usize = 64;

/// An account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    id: UserId,
    email: Email,
}

impl User {
    /// Creates a user.
    #[must_use]
    pub fn new(id: UserId, email: Email) -> Self {
        Self { id, email }
    }

    /// The user's identifier.
    #[must_use]
    pub fn id(&self) -> UserId {
        self.id
    }

    /// The user's email address.
    #[must_use]
    pub fn email(&self) -> &Email {
        &self.email
    }
}

/// A device that a user has signed in from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    id: DeviceId,
    user_id: UserId,
    name: String,
    revoked: bool,
}

impl Device {
    /// Creates an active device. The name is trimmed and must be 1 to
    /// [`MAX_DEVICE_NAME_LEN`] characters long once trimmed.
    pub fn new(id: DeviceId, user_id: UserId, name: &str) -> Result<Self, DomainError> {
        let normalized = name.trim();
        if normalized.is_empty() || normalized.chars().count() > MAX_DEVICE_NAME_LEN {
            return Err(DomainError::InvalidName);
        }

        Ok(Self {
            id,
            user_id,
            name: String::from(normalized),
            revoked: false,
        })
    }

    /// Marks the device as revoked. Revoking twice is harmless.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Whether the device has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// The device's identifier.
    #[must_use]
    pub fn id(&self) -> DeviceId {
        self.id
    }

    /// The owner.
    #[must_use]
    pub fn user_id(&self) -> UserId {
        self.user_id
    }

    /// The (trimmed) display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A folder. Its name is encrypted by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    id: FolderId,
    user_id: UserId,
    name: Vec<u8>,
}

impl Folder {
    /// Creates a folder.
    #[must_use]
    pub fn new(id: FolderId, user_id: UserId, name: Vec<u8>) -> Self {
        Self { id, user_id, name }
    }

    /// The folder's identifier.
    #[must_use]
    pub fn id(&self) -> FolderId {
        self.id
    }

    /// The owner.
    #[must_use]
    pub fn user_id(&self) -> UserId {
        self.user_id
    }

    /// The encrypted name.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }
}

/// An encrypted vault item, or the tombstone left behind when it is deleted.
///
/// A tombstone keeps the identifier and the revision (so that other devices learn about the
/// deletion when they sync) but holds no data: the server must not keep the ciphertext of
/// something the user deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cipher {
    id: CipherId,
    user_id: UserId,
    folder_id: Option<FolderId>,
    data: Vec<u8>,
    revision: Revision,
    deleted: bool,
}

impl Cipher {
    /// Creates a live cipher that last changed at `revision`.
    #[must_use]
    pub fn new(
        id: CipherId,
        user_id: UserId,
        folder_id: Option<FolderId>,
        data: Vec<u8>,
        revision: Revision,
    ) -> Self {
        Self {
            id,
            user_id,
            folder_id,
            data,
            revision,
            deleted: false,
        }
    }

    /// Turns the cipher into a tombstone changed at `revision`: the data is dropped and the
    /// cipher no longer belongs to a folder.
    pub fn delete(&mut self, revision: Revision) {
        self.revision = revision;
        self.deleted = true;
        self.data.clear();
        self.folder_id = None;
    }

    /// Whether the cipher is a tombstone.
    #[must_use]
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    /// The cipher's identifier.
    #[must_use]
    pub fn id(&self) -> CipherId {
        self.id
    }

    /// The owner.
    #[must_use]
    pub fn user_id(&self) -> UserId {
        self.user_id
    }

    /// The folder it is filed in, if any.
    #[must_use]
    pub fn folder_id(&self) -> Option<FolderId> {
        self.folder_id
    }

    /// The encrypted payload (empty for a tombstone).
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// The revision at which the cipher last changed.
    #[must_use]
    pub fn revision(&self) -> Revision {
        self.revision
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn user_id() -> UserId {
        UserId::from_uuid(Uuid::from_u128(1))
    }

    fn device(name: &str) -> Result<Device, DomainError> {
        Device::new(DeviceId::from_uuid(Uuid::from_u128(2)), user_id(), name)
    }

    fn cipher() -> Cipher {
        Cipher::new(
            CipherId::from_uuid(Uuid::from_u128(3)),
            user_id(),
            Some(FolderId::from_uuid(Uuid::from_u128(4))),
            vec![1, 2, 3],
            Revision::new(5),
        )
    }

    #[test]
    fn user_exposes_what_it_was_built_with() {
        let email = Email::parse("manu@example.com").unwrap();
        let user = User::new(user_id(), email.clone());
        assert_eq!(user.id(), user_id());
        assert_eq!(user.email(), &email);
    }

    #[test]
    fn new_device_is_active_and_belongs_to_the_user() {
        let device = device("Pixel 8").unwrap();
        assert!(!device.is_revoked());
        assert_eq!(device.user_id(), user_id());
        assert_eq!(device.name(), "Pixel 8");
    }

    #[test]
    fn device_name_is_trimmed() {
        assert_eq!(device("  Laptop \n").unwrap().name(), "Laptop");
    }

    #[test]
    fn device_name_must_not_be_blank() {
        assert_eq!(device(""), Err(DomainError::InvalidName));
        assert_eq!(device("   "), Err(DomainError::InvalidName));
    }

    #[test]
    fn device_name_length_limit() {
        assert!(device(&"a".repeat(MAX_DEVICE_NAME_LEN)).is_ok());
        assert_eq!(
            device(&"a".repeat(MAX_DEVICE_NAME_LEN + 1)),
            Err(DomainError::InvalidName)
        );
    }

    #[test]
    fn revoking_a_device_is_permanent_and_idempotent() {
        let mut device = device("Pixel 8").unwrap();
        device.revoke();
        assert!(device.is_revoked());
        device.revoke();
        assert!(device.is_revoked());
    }

    #[test]
    fn folder_keeps_its_encrypted_name() {
        let folder = Folder::new(
            FolderId::from_uuid(Uuid::from_u128(4)),
            user_id(),
            vec![9, 9],
        );
        assert_eq!(folder.name(), &[9, 9]);
        assert_eq!(folder.user_id(), user_id());
    }

    #[test]
    fn new_cipher_is_live() {
        let cipher = cipher();
        assert!(!cipher.is_deleted());
        assert_eq!(cipher.data(), &[1, 2, 3]);
        assert_eq!(cipher.revision(), Revision::new(5));
    }

    #[test]
    fn deleting_a_cipher_leaves_a_tombstone_without_data() {
        let mut cipher = cipher();
        let (id, owner) = (cipher.id(), cipher.user_id());
        cipher.delete(Revision::new(6));
        assert!(cipher.is_deleted());
        assert!(cipher.data().is_empty());
        assert_eq!(cipher.folder_id(), None);
        assert_eq!(cipher.revision(), Revision::new(6));
        assert_eq!((cipher.id(), cipher.user_id()), (id, owner));
    }
}
