//! Ports: interfaces the domain requires from the outer layers.
//!
//! Implementations live in `server-data` (storage) or in the binary (everything else).
//! See ADR 0007 for the rules every implementation must follow.

use std::future::Future;

use crate::{
    Cipher, CipherId, Device, DeviceId, DomainError, Email, Revision, Timestamp, User, UserId,
};

/// Checks that storage is responding. Used by the health endpoint.
pub trait StorageProbe: Send + Sync {
    /// Returns `Ok(())` if storage is reachable.
    fn ping(&self) -> impl Future<Output = Result<(), DomainError>> + Send;
}

/// Source of the current time. Injected, so tests can fix it.
pub trait Clock: Send + Sync {
    /// The current time.
    fn now(&self) -> Timestamp;
}

/// Storage of user accounts and of each user's revision counter.
pub trait UserRepository: Send + Sync {
    /// Stores a new user. Fails with [`DomainError::Conflict`] if the email is taken.
    fn insert(&self, user: &User) -> impl Future<Output = Result<(), DomainError>> + Send;

    /// Finds a user by identifier.
    fn find_by_id(
        &self,
        id: UserId,
    ) -> impl Future<Output = Result<Option<User>, DomainError>> + Send;

    /// Finds a user by (normalised) email.
    fn find_by_email(
        &self,
        email: &Email,
    ) -> impl Future<Output = Result<Option<User>, DomainError>> + Send;

    /// The user's current revision ([`Revision::ZERO`] if nothing has changed yet).
    fn revision(&self, id: UserId) -> impl Future<Output = Result<Revision, DomainError>> + Send;

    /// Atomically increments the user's revision and returns the new value.
    fn bump_revision(
        &self,
        id: UserId,
    ) -> impl Future<Output = Result<Revision, DomainError>> + Send;
}

/// Storage of devices. Every lookup also names the owner.
pub trait DeviceRepository: Send + Sync {
    /// Stores a new device.
    fn insert(&self, device: &Device) -> impl Future<Output = Result<(), DomainError>> + Send;

    /// Finds a device of `user_id`; a device of another user is simply not found.
    fn find(
        &self,
        user_id: UserId,
        id: DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, DomainError>> + Send;

    /// Saves the changes to an existing device (for example its revocation).
    fn update(&self, device: &Device) -> impl Future<Output = Result<(), DomainError>> + Send;
}

/// Storage of ciphers and tombstones. Every operation names the owner.
pub trait CipherRepository: Send + Sync {
    /// Stores a new cipher.
    fn insert(&self, cipher: &Cipher) -> impl Future<Output = Result<(), DomainError>> + Send;

    /// Finds a cipher (or tombstone) of `user_id`; one of another user is simply not found.
    fn find(
        &self,
        user_id: UserId,
        id: CipherId,
    ) -> impl Future<Output = Result<Option<Cipher>, DomainError>> + Send;

    /// Replaces a stored cipher, but only if it is still at `expected`; otherwise fails with
    /// [`DomainError::Conflict`].
    fn update(
        &self,
        cipher: &Cipher,
        expected: Revision,
    ) -> impl Future<Output = Result<(), DomainError>> + Send;

    /// Everything of `user_id` that changed after `since`, tombstones included,
    /// in increasing revision order.
    fn changes_since(
        &self,
        user_id: UserId,
        since: Revision,
    ) -> impl Future<Output = Result<Vec<Cipher>, DomainError>> + Send;
}

/// A unit of work: the repositories seen through one transaction.
///
/// Dropping it without calling [`Transaction::commit`] discards every change.
pub trait Transaction: UserRepository + DeviceRepository + CipherRepository {
    /// Makes all the changes permanent.
    fn commit(self) -> impl Future<Output = Result<(), DomainError>> + Send;
}

/// Starts transactions. Transactions are the domain's responsibility: a service decides
/// what must succeed or fail together, the storage only provides the mechanism.
pub trait UnitOfWork: Send + Sync {
    /// The transaction type.
    type Tx: Transaction + Send;

    /// Begins a transaction.
    fn begin(&self) -> impl Future<Output = Result<Self::Tx, DomainError>> + Send;
}
