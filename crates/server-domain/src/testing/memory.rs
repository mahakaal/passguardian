//! In-memory implementation of the storage ports.

use std::future::{ready, Future};

use crate::ports::{
    CipherRepository, DeviceRepository, StorageProbe, Transaction, UnitOfWork, UserRepository,
};
use crate::{Cipher, CipherId, Device, DeviceId, DomainError, Email, Revision, User, UserId};

/// Storage kept in memory. Clones share the same data.
#[derive(Debug, Clone, Default)]
pub struct InMemoryStore {}

impl InMemoryStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// A transaction on an [`InMemoryStore`].
#[derive(Debug)]
pub struct InMemoryTransaction {}

impl StorageProbe for InMemoryStore {
    fn ping(&self) -> impl Future<Output = Result<(), DomainError>> + Send {
        ready(Err(DomainError::Unavailable))
    }
}

impl UnitOfWork for InMemoryStore {
    type Tx = InMemoryTransaction;

    fn begin(&self) -> impl Future<Output = Result<Self::Tx, DomainError>> + Send {
        ready(Err(DomainError::Unavailable))
    }
}

impl Transaction for InMemoryTransaction {
    fn commit(self) -> impl Future<Output = Result<(), DomainError>> + Send {
        ready(Err(DomainError::Unavailable))
    }
}

impl UserRepository for InMemoryTransaction {
    fn insert(&self, _user: &User) -> impl Future<Output = Result<(), DomainError>> + Send {
        ready(Err(DomainError::Unavailable))
    }

    fn find_by_id(
        &self,
        _id: UserId,
    ) -> impl Future<Output = Result<Option<User>, DomainError>> + Send {
        ready(Err(DomainError::Unavailable))
    }

    fn find_by_email(
        &self,
        _email: &Email,
    ) -> impl Future<Output = Result<Option<User>, DomainError>> + Send {
        ready(Err(DomainError::Unavailable))
    }

    fn revision(&self, _id: UserId) -> impl Future<Output = Result<Revision, DomainError>> + Send {
        ready(Err(DomainError::Unavailable))
    }

    fn bump_revision(
        &self,
        _id: UserId,
    ) -> impl Future<Output = Result<Revision, DomainError>> + Send {
        ready(Err(DomainError::Unavailable))
    }
}

impl DeviceRepository for InMemoryTransaction {
    fn insert(&self, _device: &Device) -> impl Future<Output = Result<(), DomainError>> + Send {
        ready(Err(DomainError::Unavailable))
    }

    fn find(
        &self,
        _user_id: UserId,
        _id: DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, DomainError>> + Send {
        ready(Err(DomainError::Unavailable))
    }

    fn update(&self, _device: &Device) -> impl Future<Output = Result<(), DomainError>> + Send {
        ready(Err(DomainError::Unavailable))
    }
}

impl CipherRepository for InMemoryTransaction {
    fn insert(&self, _cipher: &Cipher) -> impl Future<Output = Result<(), DomainError>> + Send {
        ready(Err(DomainError::Unavailable))
    }

    fn find(
        &self,
        _user_id: UserId,
        _id: CipherId,
    ) -> impl Future<Output = Result<Option<Cipher>, DomainError>> + Send {
        ready(Err(DomainError::Unavailable))
    }

    fn update(
        &self,
        _cipher: &Cipher,
        _expected: Revision,
    ) -> impl Future<Output = Result<(), DomainError>> + Send {
        ready(Err(DomainError::Unavailable))
    }

    fn changes_since(
        &self,
        _user_id: UserId,
        _since: Revision,
    ) -> impl Future<Output = Result<Vec<Cipher>, DomainError>> + Send {
        ready(Err(DomainError::Unavailable))
    }
}
