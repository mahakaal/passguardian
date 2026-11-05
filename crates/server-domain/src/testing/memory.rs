//! In-memory implementation of the storage ports.
//!
//! A transaction works on its own copy of the data. Committing publishes the copy, unless
//! another transaction committed in the meantime (then it fails with `Conflict`); dropping
//! it simply throws the copy away.

use std::collections::HashMap;
use std::future::{ready, Future};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::ports::{
    CipherRepository, DeviceRepository, StorageProbe, Transaction, UnitOfWork, UserRepository,
};
use crate::{Cipher, CipherId, Device, DeviceId, DomainError, Email, Revision, User, UserId};

#[derive(Debug, Clone, Default)]
struct State {
    users: HashMap<UserId, User>,
    revisions: HashMap<UserId, Revision>,
    devices: HashMap<DeviceId, Device>,
    ciphers: HashMap<CipherId, Cipher>,
    /// Number of commits so far, to detect concurrent transactions.
    version: u64,
}

/// A poisoned lock means a test already panicked; report it as storage being unavailable.
fn lock(state: &Mutex<State>) -> Result<MutexGuard<'_, State>, DomainError> {
    state.lock().map_err(|_| DomainError::Unavailable)
}

/// Storage kept in memory. Clones share the same data.
#[derive(Debug, Clone, Default)]
pub struct InMemoryStore {
    shared: Arc<Mutex<State>>,
}

impl InMemoryStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// A transaction on an [`InMemoryStore`].
#[derive(Debug)]
pub struct InMemoryTransaction {
    shared: Arc<Mutex<State>>,
    working: Mutex<State>,
}

impl InMemoryTransaction {
    fn with<T>(
        &self,
        f: impl FnOnce(&mut State) -> Result<T, DomainError>,
    ) -> Result<T, DomainError> {
        f(&mut *lock(&self.working)?)
    }
}

impl StorageProbe for InMemoryStore {
    fn ping(&self) -> impl Future<Output = Result<(), DomainError>> + Send {
        ready(lock(&self.shared).map(|_| ()))
    }
}

impl UnitOfWork for InMemoryStore {
    type Tx = InMemoryTransaction;

    fn begin(&self) -> impl Future<Output = Result<Self::Tx, DomainError>> + Send {
        ready(lock(&self.shared).map(|state| InMemoryTransaction {
            shared: Arc::clone(&self.shared),
            working: Mutex::new(state.clone()),
        }))
    }
}

impl Transaction for InMemoryTransaction {
    fn commit(self) -> impl Future<Output = Result<(), DomainError>> + Send {
        let result = self
            .working
            .into_inner()
            .map_err(|_| DomainError::Unavailable)
            .and_then(|mut working| {
                let mut shared = lock(&self.shared)?;
                if shared.version != working.version {
                    return Err(DomainError::Conflict);
                }
                working.version += 1;
                *shared = working;
                Ok(())
            });
        ready(result)
    }
}

impl UserRepository for InMemoryTransaction {
    fn insert(&self, user: &User) -> impl Future<Output = Result<(), DomainError>> + Send {
        ready(self.with(|state| {
            let taken = state
                .users
                .values()
                .any(|u| u.id() == user.id() || u.email() == user.email());
            if taken {
                return Err(DomainError::Conflict);
            }
            state.users.insert(user.id(), user.clone());
            Ok(())
        }))
    }

    fn find_by_id(
        &self,
        id: UserId,
    ) -> impl Future<Output = Result<Option<User>, DomainError>> + Send {
        ready(self.with(|state| Ok(state.users.get(&id).cloned())))
    }

    fn find_by_email(
        &self,
        email: &Email,
    ) -> impl Future<Output = Result<Option<User>, DomainError>> + Send {
        ready(self.with(|state| Ok(state.users.values().find(|u| u.email() == email).cloned())))
    }

    fn revision(&self, id: UserId) -> impl Future<Output = Result<Revision, DomainError>> + Send {
        ready(self.with(|state| Ok(state.revisions.get(&id).copied().unwrap_or(Revision::ZERO))))
    }

    fn bump_revision(
        &self,
        id: UserId,
    ) -> impl Future<Output = Result<Revision, DomainError>> + Send {
        ready(self.with(|state| {
            if !state.users.contains_key(&id) {
                return Err(DomainError::Conflict);
            }
            let revision = state.revisions.entry(id).or_insert(Revision::ZERO);
            *revision = revision.next()?;
            Ok(*revision)
        }))
    }
}

impl DeviceRepository for InMemoryTransaction {
    fn insert(&self, device: &Device) -> impl Future<Output = Result<(), DomainError>> + Send {
        ready(self.with(|state| {
            if state.devices.contains_key(&device.id()) {
                return Err(DomainError::Conflict);
            }
            state.devices.insert(device.id(), device.clone());
            Ok(())
        }))
    }

    fn find(
        &self,
        user_id: UserId,
        id: DeviceId,
    ) -> impl Future<Output = Result<Option<Device>, DomainError>> + Send {
        ready(self.with(|state| {
            Ok(state
                .devices
                .get(&id)
                .filter(|d| d.user_id() == user_id)
                .cloned())
        }))
    }

    fn update(&self, device: &Device) -> impl Future<Output = Result<(), DomainError>> + Send {
        ready(
            self.with(|state| match state.devices.get_mut(&device.id()) {
                Some(stored) if stored.user_id() == device.user_id() => {
                    *stored = device.clone();
                    Ok(())
                }
                _ => Err(DomainError::Conflict),
            }),
        )
    }
}

impl CipherRepository for InMemoryTransaction {
    fn insert(&self, cipher: &Cipher) -> impl Future<Output = Result<(), DomainError>> + Send {
        ready(self.with(|state| {
            if state.ciphers.contains_key(&cipher.id()) {
                return Err(DomainError::Conflict);
            }
            state.ciphers.insert(cipher.id(), cipher.clone());
            Ok(())
        }))
    }

    fn find(
        &self,
        user_id: UserId,
        id: CipherId,
    ) -> impl Future<Output = Result<Option<Cipher>, DomainError>> + Send {
        ready(self.with(|state| {
            Ok(state
                .ciphers
                .get(&id)
                .filter(|c| c.user_id() == user_id)
                .cloned())
        }))
    }

    fn update(
        &self,
        cipher: &Cipher,
        expected: Revision,
    ) -> impl Future<Output = Result<(), DomainError>> + Send {
        ready(
            self.with(|state| match state.ciphers.get_mut(&cipher.id()) {
                Some(stored)
                    if stored.user_id() == cipher.user_id() && stored.revision() == expected =>
                {
                    *stored = cipher.clone();
                    Ok(())
                }
                _ => Err(DomainError::Conflict),
            }),
        )
    }

    fn changes_since(
        &self,
        user_id: UserId,
        since: Revision,
    ) -> impl Future<Output = Result<Vec<Cipher>, DomainError>> + Send {
        ready(self.with(|state| {
            let mut changes: Vec<Cipher> = state
                .ciphers
                .values()
                .filter(|c| c.user_id() == user_id && c.revision() > since)
                .cloned()
                .collect();
            changes.sort_by_key(Cipher::revision);
            Ok(changes)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn concurrent_commits_conflict() {
        let store = InMemoryStore::new();
        let first = store.begin().await.unwrap();
        let second = store.begin().await.unwrap();
        first.commit().await.unwrap();
        assert_eq!(second.commit().await, Err(DomainError::Conflict));
    }

    #[tokio::test]
    async fn clones_share_the_same_data() {
        let store = InMemoryStore::new();
        let user = User::new(
            UserId::from_uuid(uuid::Uuid::from_u128(1)),
            Email::parse("alice@example.com").unwrap(),
        );
        let tx = store.clone().begin().await.unwrap();
        UserRepository::insert(&tx, &user).await.unwrap();
        tx.commit().await.unwrap();

        let tx = store.begin().await.unwrap();
        assert_eq!(tx.find_by_id(user.id()).await.unwrap(), Some(user));
    }
}
