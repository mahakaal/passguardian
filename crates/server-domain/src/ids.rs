//! Typed identifiers.
//!
//! Each entity has its own identifier type, so the compiler refuses to pass a `UserId`
//! where a `DeviceId` is expected. They wrap a UUID but never generate one: randomness is
//! an input of the domain, not something it produces (see the `Clock` port in PG-24).

// TODO(PG-23): remove this line once the `todo!()` bodies are implemented.
#![allow(unused_variables)]

use std::{fmt, str::FromStr};

use uuid::Uuid;

use crate::DomainError;

/// Identifier of a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId(Uuid);

impl UserId {
    /// Wraps an existing UUID.
    #[must_use]
    pub fn from_uuid(uuid: Uuid) -> Self {
        todo!()
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub fn as_uuid(&self) -> Uuid {
        todo!()
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl FromStr for UserId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

/// Identifier of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(Uuid);

impl DeviceId {
    /// Wraps an existing UUID.
    #[must_use]
    pub fn from_uuid(uuid: Uuid) -> Self {
        todo!()
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub fn as_uuid(&self) -> Uuid {
        todo!()
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl FromStr for DeviceId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

/// Identifier of a cipher (an encrypted vault item).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CipherId(Uuid);

impl CipherId {
    /// Wraps an existing UUID.
    #[must_use]
    pub fn from_uuid(uuid: Uuid) -> Self {
        todo!()
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub fn as_uuid(&self) -> Uuid {
        todo!()
    }
}

impl fmt::Display for CipherId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl FromStr for CipherId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

/// Identifier of a folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FolderId(Uuid);

impl FolderId {
    /// Wraps an existing UUID.
    #[must_use]
    pub fn from_uuid(uuid: Uuid) -> Self {
        todo!()
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub fn as_uuid(&self) -> Uuid {
        todo!()
    }
}

impl fmt::Display for FolderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl FromStr for FolderId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";

    #[test]
    fn from_uuid_and_as_uuid_roundtrip() {
        let uuid = Uuid::from_u128(42);
        assert_eq!(UserId::from_uuid(uuid).as_uuid(), uuid);
    }

    #[test]
    fn display_is_the_hyphenated_lowercase_uuid() {
        let id = UserId::from_uuid(Uuid::from_u128(1));
        assert_eq!(id.to_string(), "00000000-0000-0000-0000-000000000001");
    }

    #[test]
    fn parses_what_it_displays() {
        let id: UserId = TEXT.parse().unwrap();
        assert_eq!(id.to_string(), TEXT);
    }

    #[test]
    fn rejects_text_that_is_not_a_uuid() {
        assert_eq!("not-a-uuid".parse::<UserId>(), Err(DomainError::InvalidId));
        assert_eq!("".parse::<UserId>(), Err(DomainError::InvalidId));
    }

    #[test]
    fn different_uuids_are_different_ids() {
        assert_ne!(
            UserId::from_uuid(Uuid::from_u128(1)),
            UserId::from_uuid(Uuid::from_u128(2))
        );
    }

    // The other three identifiers must behave exactly like `UserId`.
    #[test]
    fn device_id_roundtrips_through_text() {
        let id: DeviceId = TEXT.parse().unwrap();
        assert_eq!(id.to_string(), TEXT);
        assert_eq!("x".parse::<DeviceId>(), Err(DomainError::InvalidId));
    }

    #[test]
    fn cipher_id_roundtrips_through_text() {
        let id: CipherId = TEXT.parse().unwrap();
        assert_eq!(id.to_string(), TEXT);
        assert_eq!("x".parse::<CipherId>(), Err(DomainError::InvalidId));
    }

    #[test]
    fn folder_id_roundtrips_through_text() {
        let id: FolderId = TEXT.parse().unwrap();
        assert_eq!(id.to_string(), TEXT);
        assert_eq!("x".parse::<FolderId>(), Err(DomainError::InvalidId));
    }
}
