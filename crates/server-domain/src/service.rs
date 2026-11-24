//! Application services: registration, login, devices, ciphers and sync.
//!
//! A service decides what must succeed or fail together and runs it inside one transaction.
//! The login secret is a 256-bit key that the client derives from the master password with a
//! different label than the encryption key (ADR 0003); the server never sees the password
//! and keeps only a hash of that key.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::ports::{
    CipherRepository, Clock, DeviceRepository, IdGenerator, Transaction, UnitOfWork, UserRepository,
};
use crate::throttle::LoginThrottle;
use crate::{
    Cipher, CipherId, Device, DeviceId, DomainError, Email, FolderId, Revision, User, UserId,
};

/// Size in bytes of the login key sent by the client.
pub const AUTH_KEY_LEN: usize = 32;

/// Failed logins allowed per [`LOGIN_WINDOW_SECONDS`] before the account is locked out.
pub const MAX_LOGIN_FAILURES: u32 = 5;

/// Length of the lockout window.
pub const LOGIN_WINDOW_SECONDS: i64 = 15 * 60;

/// What a client sends to create an account.
#[derive(Debug, Clone, Copy)]
pub struct Registration<'a> {
    /// The email address (normalised by the service).
    pub email: &'a str,
    /// The login key derived on the client ([`AUTH_KEY_LEN`] bytes).
    pub auth_key: &'a [u8],
    /// The client's key envelope: KDF parameters, salt and wrapped vault key. Opaque here.
    pub key_envelope: &'a [u8],
    /// A name for the first device.
    pub device_name: &'a str,
}

/// The result of a successful registration or login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The authenticated user.
    pub user_id: UserId,
    /// The device this session belongs to.
    pub device_id: DeviceId,
    /// The key envelope the client needs to unlock its vault.
    pub key_envelope: Vec<u8>,
}

/// Everything that changed after a revision, plus the revision to ask from next time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncResponse {
    /// The user's current revision.
    pub revision: Revision,
    /// Changed ciphers and tombstones, in increasing revision order.
    pub changes: Vec<Cipher>,
}

/// The server's use cases, generic over storage, time and identifiers.
#[derive(Debug)]
pub struct Service<U, C, G> {
    uow: U,
    clock: C,
    ids: G,
    throttle: LoginThrottle,
}

fn auth_hash(user_id: UserId, auth_key: &[u8]) -> Vec<u8> {
    Sha256::new()
        .chain_update(b"passguardian/v1/auth")
        .chain_update(user_id.as_uuid().as_bytes())
        .chain_update(auth_key)
        .finalize()
        .to_vec()
}

impl<U: UnitOfWork, C: Clock, G: IdGenerator> Service<U, C, G> {
    /// Creates the service.
    #[must_use]
    pub fn new(uow: U, clock: C, ids: G) -> Self {
        Self {
            uow,
            clock,
            ids,
            throttle: LoginThrottle::new(MAX_LOGIN_FAILURES, LOGIN_WINDOW_SECONDS),
        }
    }

    /// Creates an account and its first device.
    ///
    /// Fails with `Conflict` if the email is already registered; the error says nothing else.
    pub async fn register(&self, input: &Registration<'_>) -> Result<Session, DomainError> {
        let email = Email::parse(input.email)?;
        if input.auth_key.len() != AUTH_KEY_LEN || input.key_envelope.is_empty() {
            return Err(DomainError::InvalidInput);
        }
        let user_id = UserId::from_uuid(self.ids.new_uuid());
        let device_id = DeviceId::from_uuid(self.ids.new_uuid());
        let user = User::new(user_id, email).with_credentials(
            auth_hash(user_id, input.auth_key),
            input.key_envelope.to_vec(),
        );
        let device = Device::new(device_id, user_id, input.device_name)?;

        let tx = self.uow.begin().await?;
        UserRepository::insert(&tx, &user).await?;
        DeviceRepository::insert(&tx, &device).await?;
        tx.commit().await?;
        Ok(Session {
            user_id,
            device_id,
            key_envelope: input.key_envelope.to_vec(),
        })
    }

    /// Checks the credentials and registers the calling device.
    ///
    /// An unknown email and a wrong key give the same error. After
    /// [`MAX_LOGIN_FAILURES`] failures the account is locked out for a while, known or not.
    pub async fn login(
        &self,
        email: &str,
        auth_key: &[u8],
        device_name: &str,
    ) -> Result<Session, DomainError> {
        let email = Email::parse(email).map_err(|_| DomainError::InvalidCredentials)?;
        let now = self.clock.now();
        self.throttle.check(email.as_str(), now)?;

        let tx = self.uow.begin().await?;
        let user = UserRepository::find_by_email(&tx, &email).await?;
        // The hash is computed for unknown users too, so both cases take the same time.
        let candidate_owner = user
            .as_ref()
            .map_or_else(|| UserId::from_uuid(uuid::Uuid::nil()), User::id);
        let candidate = auth_hash(candidate_owner, auth_key);
        let stored: &[u8] = user.as_ref().map_or(&[], User::auth_hash);
        let matches = bool::from(candidate.as_slice().ct_eq(stored));

        let Some(user) = user.filter(|_| matches) else {
            self.throttle.record_failure(email.as_str(), now)?;
            return Err(DomainError::InvalidCredentials);
        };
        self.throttle.reset(email.as_str())?;

        let device = Device::new(
            DeviceId::from_uuid(self.ids.new_uuid()),
            user.id(),
            device_name,
        )?;
        DeviceRepository::insert(&tx, &device).await?;
        tx.commit().await?;
        Ok(Session {
            user_id: user.id(),
            device_id: device.id(),
            key_envelope: user.key_envelope().to_vec(),
        })
    }

    /// Checks that a device may still obtain new tokens.
    pub async fn refresh(&self, user_id: UserId, device_id: DeviceId) -> Result<(), DomainError> {
        let tx = self.uow.begin().await?;
        match DeviceRepository::find(&tx, user_id, device_id).await? {
            Some(device) if !device.is_revoked() => Ok(()),
            _ => Err(DomainError::InvalidCredentials),
        }
    }

    /// Revokes one of the user's devices.
    pub async fn revoke_device(
        &self,
        user_id: UserId,
        device_id: DeviceId,
    ) -> Result<(), DomainError> {
        let tx = self.uow.begin().await?;
        let mut device = DeviceRepository::find(&tx, user_id, device_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        device.revoke();
        DeviceRepository::update(&tx, &device).await?;
        tx.commit().await
    }

    /// Stores a new cipher whose identifier was chosen by the client.
    pub async fn create_cipher(
        &self,
        user_id: UserId,
        cipher_id: CipherId,
        folder_id: Option<FolderId>,
        data: Vec<u8>,
    ) -> Result<Cipher, DomainError> {
        let tx = self.uow.begin().await?;
        let revision = UserRepository::bump_revision(&tx, user_id).await?;
        let cipher = Cipher::new(cipher_id, user_id, folder_id, data, revision);
        CipherRepository::insert(&tx, &cipher).await?;
        tx.commit().await?;
        Ok(cipher)
    }

    /// Replaces a cipher, provided the caller saw its latest revision (`expected`).
    pub async fn update_cipher(
        &self,
        user_id: UserId,
        cipher_id: CipherId,
        expected: Revision,
        folder_id: Option<FolderId>,
        data: Vec<u8>,
    ) -> Result<Cipher, DomainError> {
        let tx = self.uow.begin().await?;
        let mut cipher = CipherRepository::find(&tx, user_id, cipher_id)
            .await?
            .filter(|c| !c.is_deleted())
            .ok_or(DomainError::NotFound)?;
        if cipher.revision() != expected {
            return Err(DomainError::Conflict);
        }
        let revision = UserRepository::bump_revision(&tx, user_id).await?;
        cipher.update(folder_id, data, revision);
        CipherRepository::update(&tx, &cipher, expected).await?;
        tx.commit().await?;
        Ok(cipher)
    }

    /// Deletes a cipher, leaving a tombstone that sync will deliver. Deleting twice is harmless.
    pub async fn delete_cipher(
        &self,
        user_id: UserId,
        cipher_id: CipherId,
        expected: Revision,
    ) -> Result<Cipher, DomainError> {
        let tx = self.uow.begin().await?;
        let mut cipher = CipherRepository::find(&tx, user_id, cipher_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        if cipher.is_deleted() {
            return Ok(cipher);
        }
        if cipher.revision() != expected {
            return Err(DomainError::Conflict);
        }
        let revision = UserRepository::bump_revision(&tx, user_id).await?;
        cipher.delete(revision);
        CipherRepository::update(&tx, &cipher, expected).await?;
        tx.commit().await?;
        Ok(cipher)
    }

    /// Returns what changed after `since`, oldest change first.
    pub async fn sync(
        &self,
        user_id: UserId,
        since: Revision,
    ) -> Result<SyncResponse, DomainError> {
        let tx = self.uow.begin().await?;
        Ok(SyncResponse {
            revision: UserRepository::revision(&tx, user_id).await?,
            changes: CipherRepository::changes_since(&tx, user_id, since).await?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{InMemoryStore, ManualClock, SequentialIds};
    use crate::Timestamp;

    type TestService = Service<InMemoryStore, ManualClock, SequentialIds>;

    const KEY: [u8; AUTH_KEY_LEN] = [7; AUTH_KEY_LEN];
    const OTHER_KEY: [u8; AUTH_KEY_LEN] = [8; AUTH_KEY_LEN];

    fn service() -> (TestService, ManualClock) {
        let clock = ManualClock::new(Timestamp::from_unix_seconds(1_000));
        (
            Service::new(InMemoryStore::new(), clock.clone(), SequentialIds::new()),
            clock,
        )
    }

    fn registration<'a>(email: &'a str, key: &'a [u8]) -> Registration<'a> {
        Registration {
            email,
            auth_key: key,
            key_envelope: b"envelope",
            device_name: "laptop",
        }
    }

    async fn alice(service: &TestService) -> Session {
        service
            .register(&registration("alice@example.com", &KEY))
            .await
            .unwrap()
    }

    async fn bob(service: &TestService) -> Session {
        service
            .register(&registration("bob@example.com", &OTHER_KEY))
            .await
            .unwrap()
    }

    fn cipher_id(n: u128) -> CipherId {
        CipherId::from_uuid(uuid::Uuid::from_u128(n))
    }

    #[tokio::test]
    async fn register_creates_user_and_first_device() {
        let (service, _) = service();
        let session = alice(&service).await;
        assert_eq!(session.key_envelope, b"envelope");
        service
            .refresh(session.user_id, session.device_id)
            .await
            .unwrap();
        let login = service
            .login("alice@example.com", &KEY, "phone")
            .await
            .unwrap();
        assert_eq!(login.user_id, session.user_id);
        assert_ne!(login.device_id, session.device_id);
    }

    #[tokio::test]
    async fn register_with_existing_email_fails_without_leaking_which_field() {
        let (service, _) = service();
        alice(&service).await;
        let error = service
            .register(&registration("ALICE@example.com", &OTHER_KEY))
            .await
            .unwrap_err();
        assert_eq!(error, DomainError::Conflict);
        assert!(!error.to_string().to_lowercase().contains("email"));
    }

    #[tokio::test]
    async fn register_rejects_malformed_input() {
        let (service, _) = service();
        assert_eq!(
            service.register(&registration("nope", &KEY)).await,
            Err(DomainError::InvalidEmail)
        );
        assert_eq!(
            service
                .register(&registration("a@example.com", &KEY[..10]))
                .await,
            Err(DomainError::InvalidInput)
        );
        let mut empty = registration("a@example.com", &KEY);
        empty.key_envelope = b"";
        assert_eq!(
            service.register(&empty).await,
            Err(DomainError::InvalidInput)
        );
    }

    #[tokio::test]
    async fn login_with_wrong_credentials_is_indistinguishable_from_unknown_user() {
        let (service, _) = service();
        alice(&service).await;
        let wrong_key = service.login("alice@example.com", &OTHER_KEY, "x").await;
        let unknown = service.login("nobody@example.com", &KEY, "x").await;
        let malformed = service.login("not an email", &KEY, "x").await;
        assert_eq!(wrong_key, Err(DomainError::InvalidCredentials));
        assert_eq!(unknown, wrong_key);
        assert_eq!(malformed, wrong_key);
    }

    #[tokio::test]
    async fn login_is_rate_limited_after_n_failures() {
        let (service, clock) = service();
        alice(&service).await;
        for _ in 0..MAX_LOGIN_FAILURES {
            assert_eq!(
                service.login("alice@example.com", &OTHER_KEY, "x").await,
                Err(DomainError::InvalidCredentials)
            );
        }
        // Even the right key is refused while locked out.
        assert_eq!(
            service.login("alice@example.com", &KEY, "x").await,
            Err(DomainError::RateLimited)
        );
        // Unknown accounts are limited the same way, so the lockout reveals nothing.
        for _ in 0..MAX_LOGIN_FAILURES {
            let _ = service.login("ghost@example.com", &KEY, "x").await;
        }
        assert_eq!(
            service.login("ghost@example.com", &KEY, "x").await,
            Err(DomainError::RateLimited)
        );
        clock.advance(LOGIN_WINDOW_SECONDS);
        assert!(service.login("alice@example.com", &KEY, "x").await.is_ok());
    }

    #[tokio::test]
    async fn revoked_device_cannot_refresh_token() {
        let (service, _) = service();
        let session = alice(&service).await;
        service
            .revoke_device(session.user_id, session.device_id)
            .await
            .unwrap();
        assert_eq!(
            service.refresh(session.user_id, session.device_id).await,
            Err(DomainError::InvalidCredentials)
        );
    }

    #[tokio::test]
    async fn create_cipher_increments_user_revision() {
        let (service, _) = service();
        let user = alice(&service).await.user_id;
        let first = service
            .create_cipher(user, cipher_id(1), None, vec![1])
            .await
            .unwrap();
        let second = service
            .create_cipher(user, cipher_id(2), None, vec![2])
            .await
            .unwrap();
        assert_eq!(first.revision(), Revision::new(1));
        assert_eq!(second.revision(), Revision::new(2));
        assert_eq!(
            service.sync(user, Revision::ZERO).await.unwrap().revision,
            Revision::new(2)
        );
    }

    #[tokio::test]
    async fn update_cipher_with_stale_revision_conflicts() {
        let (service, _) = service();
        let user = alice(&service).await.user_id;
        let created = service
            .create_cipher(user, cipher_id(1), None, vec![1])
            .await
            .unwrap();
        let updated = service
            .update_cipher(user, cipher_id(1), created.revision(), None, vec![2])
            .await
            .unwrap();
        assert_eq!(updated.data(), &[2]);
        assert_eq!(updated.revision(), Revision::new(2));
        // A second writer still holding the old revision loses.
        assert_eq!(
            service
                .update_cipher(user, cipher_id(1), created.revision(), None, vec![3])
                .await,
            Err(DomainError::Conflict)
        );
    }

    #[tokio::test]
    async fn delete_cipher_creates_tombstone_and_is_returned_by_sync() {
        let (service, _) = service();
        let user = alice(&service).await.user_id;
        let created = service
            .create_cipher(user, cipher_id(1), None, vec![1])
            .await
            .unwrap();
        let tombstone = service
            .delete_cipher(user, cipher_id(1), created.revision())
            .await
            .unwrap();
        assert!(tombstone.is_deleted());
        assert_eq!(tombstone.data(), []);

        let sync = service.sync(user, created.revision()).await.unwrap();
        assert_eq!(sync.changes.len(), 1);
        assert!(sync.changes[0].is_deleted());
        // Deleting again is harmless, and a deleted cipher cannot be edited.
        assert!(service
            .delete_cipher(user, cipher_id(1), created.revision())
            .await
            .is_ok());
        assert_eq!(
            service
                .update_cipher(user, cipher_id(1), tombstone.revision(), None, vec![9])
                .await,
            Err(DomainError::NotFound)
        );
    }

    #[tokio::test]
    async fn sync_since_returns_only_newer_changes_in_order() {
        let (service, _) = service();
        let user = alice(&service).await.user_id;
        for n in 1..=3 {
            service
                .create_cipher(user, cipher_id(n), None, vec![0])
                .await
                .unwrap();
        }
        let all = service.sync(user, Revision::ZERO).await.unwrap();
        assert_eq!(all.changes.len(), 3);
        let newer = service.sync(user, Revision::new(1)).await.unwrap();
        let revisions: Vec<u64> = newer.changes.iter().map(|c| c.revision().get()).collect();
        assert_eq!(revisions, vec![2, 3]);
        assert_eq!(newer.revision, Revision::new(3));
        let nothing_new = service.sync(user, Revision::new(3)).await.unwrap();
        assert_eq!(nothing_new.changes, []);
    }

    #[tokio::test]
    async fn user_cannot_read_or_modify_another_users_ciphers() {
        let (service, _) = service();
        let alice = alice(&service).await.user_id;
        let bob = bob(&service).await.user_id;
        let secret = service
            .create_cipher(alice, cipher_id(1), None, vec![42])
            .await
            .unwrap();

        // Bob sees nothing of Alice's, and cannot touch it.
        let seen_by_bob = service.sync(bob, Revision::ZERO).await.unwrap();
        assert_eq!(seen_by_bob.changes, []);
        assert_eq!(
            service
                .update_cipher(bob, cipher_id(1), secret.revision(), None, vec![0])
                .await,
            Err(DomainError::NotFound)
        );
        assert_eq!(
            service
                .delete_cipher(bob, cipher_id(1), secret.revision())
                .await,
            Err(DomainError::NotFound)
        );
        // Alice's data is intact.
        let sync = service.sync(alice, Revision::ZERO).await.unwrap();
        assert_eq!(sync.changes.len(), 1);
        assert_eq!(sync.changes[0].data(), &[42]);
    }

    #[tokio::test]
    async fn user_cannot_revoke_another_users_device() {
        let (service, _) = service();
        let alice = alice(&service).await;
        let bob = bob(&service).await;
        assert_eq!(
            service.revoke_device(bob.user_id, alice.device_id).await,
            Err(DomainError::NotFound)
        );
        assert!(service
            .refresh(alice.user_id, alice.device_id)
            .await
            .is_ok());
    }
}
