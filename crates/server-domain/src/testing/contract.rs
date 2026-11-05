//! Contract tests for the storage ports (ADR 0007).
//!
//! Every function checks one rule against a fresh, empty store and panics if the rule is
//! broken. Run them all with [`repository_contract_tests!`](crate::repository_contract_tests).

// The checks fail by panicking, like any test.
#![allow(clippy::missing_panics_doc)]

use uuid::Uuid;

use crate::ports::{CipherRepository, DeviceRepository, Transaction, UnitOfWork, UserRepository};
use crate::{Cipher, CipherId, Device, DeviceId, DomainError, Email, Revision, User, UserId};

fn alice() -> Result<User, DomainError> {
    Ok(User::new(user_id(1), Email::parse("alice@example.com")?))
}

fn bob() -> Result<User, DomainError> {
    Ok(User::new(user_id(2), Email::parse("bob@example.com")?))
}

fn user_id(n: u128) -> UserId {
    UserId::from_uuid(Uuid::from_u128(n))
}

fn device(n: u128, owner: UserId) -> Result<Device, DomainError> {
    Device::new(DeviceId::from_uuid(Uuid::from_u128(n)), owner, "laptop")
}

fn cipher(n: u128, owner: UserId, revision: Revision) -> Cipher {
    let data = n.to_le_bytes().to_vec();
    Cipher::new(
        CipherId::from_uuid(Uuid::from_u128(n)),
        owner,
        None,
        data,
        revision,
    )
}

/// A committed user is found by identifier and by email.
pub async fn inserted_user_is_found_by_id_and_email<U: UnitOfWork>(
    uow: &U,
) -> Result<(), DomainError> {
    let alice = alice()?;
    let tx = uow.begin().await?;
    UserRepository::insert(&tx, &alice).await?;
    tx.commit().await?;

    let tx = uow.begin().await?;
    assert_eq!(tx.find_by_id(alice.id()).await?, Some(alice.clone()));
    assert_eq!(tx.find_by_email(alice.email()).await?, Some(alice));
    Ok(())
}

/// A second user with the same email is rejected with `Conflict`.
pub async fn user_with_taken_email_conflicts<U: UnitOfWork>(uow: &U) -> Result<(), DomainError> {
    let alice = alice()?;
    let tx = uow.begin().await?;
    UserRepository::insert(&tx, &alice).await?;
    tx.commit().await?;

    let impostor = User::new(user_id(3), alice.email().clone());
    let tx = uow.begin().await?;
    assert_eq!(
        UserRepository::insert(&tx, &impostor).await,
        Err(DomainError::Conflict)
    );
    Ok(())
}

/// Looking up a user that does not exist finds nothing.
pub async fn unknown_user_is_not_found<U: UnitOfWork>(uow: &U) -> Result<(), DomainError> {
    let alice = alice()?;
    let tx = uow.begin().await?;
    assert_eq!(tx.find_by_id(alice.id()).await?, None);
    assert_eq!(tx.find_by_email(alice.email()).await?, None);
    Ok(())
}

/// A new user is at revision zero, and each bump adds one.
pub async fn user_revision_starts_at_zero_and_increments_by_one<U: UnitOfWork>(
    uow: &U,
) -> Result<(), DomainError> {
    let alice = alice()?;
    let tx = uow.begin().await?;
    UserRepository::insert(&tx, &alice).await?;
    assert_eq!(tx.revision(alice.id()).await?, Revision::ZERO);
    assert_eq!(tx.bump_revision(alice.id()).await?, Revision::new(1));
    assert_eq!(tx.bump_revision(alice.id()).await?, Revision::new(2));
    tx.commit().await?;

    let tx = uow.begin().await?;
    assert_eq!(tx.revision(alice.id()).await?, Revision::new(2));
    Ok(())
}

/// A device is found by its owner and by nobody else.
pub async fn inserted_device_is_found_by_its_owner_only<U: UnitOfWork>(
    uow: &U,
) -> Result<(), DomainError> {
    let (alice, bob) = (alice()?, bob()?);
    let laptop = device(10, alice.id())?;
    let tx = uow.begin().await?;
    UserRepository::insert(&tx, &alice).await?;
    UserRepository::insert(&tx, &bob).await?;
    DeviceRepository::insert(&tx, &laptop).await?;
    tx.commit().await?;

    let tx = uow.begin().await?;
    assert_eq!(
        DeviceRepository::find(&tx, alice.id(), laptop.id()).await?,
        Some(laptop.clone())
    );
    assert_eq!(
        DeviceRepository::find(&tx, bob.id(), laptop.id()).await?,
        None
    );
    Ok(())
}

/// Revoking a device and saving it is permanent.
pub async fn updated_device_stays_revoked<U: UnitOfWork>(uow: &U) -> Result<(), DomainError> {
    let alice = alice()?;
    let mut laptop = device(10, alice.id())?;
    let tx = uow.begin().await?;
    UserRepository::insert(&tx, &alice).await?;
    DeviceRepository::insert(&tx, &laptop).await?;
    tx.commit().await?;

    laptop.revoke();
    let tx = uow.begin().await?;
    DeviceRepository::update(&tx, &laptop).await?;
    tx.commit().await?;

    let tx = uow.begin().await?;
    let stored = DeviceRepository::find(&tx, alice.id(), laptop.id()).await?;
    assert!(stored.is_some_and(|d| d.is_revoked()));
    Ok(())
}

/// A cipher is found by its owner and by nobody else, byte for byte.
pub async fn inserted_cipher_is_found_by_its_owner_only<U: UnitOfWork>(
    uow: &U,
) -> Result<(), DomainError> {
    let (alice, bob) = (alice()?, bob()?);
    let tx = uow.begin().await?;
    UserRepository::insert(&tx, &alice).await?;
    UserRepository::insert(&tx, &bob).await?;
    let secret = cipher(20, alice.id(), tx.bump_revision(alice.id()).await?);
    CipherRepository::insert(&tx, &secret).await?;
    tx.commit().await?;

    let tx = uow.begin().await?;
    assert_eq!(
        CipherRepository::find(&tx, alice.id(), secret.id()).await?,
        Some(secret.clone())
    );
    assert_eq!(
        CipherRepository::find(&tx, bob.id(), secret.id()).await?,
        None
    );
    Ok(())
}

/// An update made at the revision the caller read is stored.
pub async fn cipher_update_at_expected_revision_succeeds<U: UnitOfWork>(
    uow: &U,
) -> Result<(), DomainError> {
    let alice = alice()?;
    let tx = uow.begin().await?;
    UserRepository::insert(&tx, &alice).await?;
    let read = tx.bump_revision(alice.id()).await?;
    let original = cipher(20, alice.id(), read);
    CipherRepository::insert(&tx, &original).await?;
    tx.commit().await?;

    let tx = uow.begin().await?;
    let changed = Cipher::new(
        original.id(),
        alice.id(),
        None,
        b"new ciphertext".to_vec(),
        tx.bump_revision(alice.id()).await?,
    );
    CipherRepository::update(&tx, &changed, read).await?;
    tx.commit().await?;

    let tx = uow.begin().await?;
    assert_eq!(
        CipherRepository::find(&tx, alice.id(), original.id()).await?,
        Some(changed)
    );
    Ok(())
}

/// An update made at an older revision fails with `Conflict` and changes nothing.
pub async fn cipher_update_at_stale_revision_conflicts<U: UnitOfWork>(
    uow: &U,
) -> Result<(), DomainError> {
    let alice = alice()?;
    let tx = uow.begin().await?;
    UserRepository::insert(&tx, &alice).await?;
    let stale = tx.bump_revision(alice.id()).await?;
    let current = cipher(20, alice.id(), tx.bump_revision(alice.id()).await?);
    CipherRepository::insert(&tx, &current).await?;
    tx.commit().await?;

    let tx = uow.begin().await?;
    let mut changed = current.clone();
    changed.delete(tx.bump_revision(alice.id()).await?);
    assert_eq!(
        CipherRepository::update(&tx, &changed, stale).await,
        Err(DomainError::Conflict)
    );
    assert_eq!(
        CipherRepository::find(&tx, alice.id(), current.id()).await?,
        Some(current)
    );
    Ok(())
}

/// Updating another user's cipher fails with `Conflict`, exactly as if it did not exist.
pub async fn cipher_update_of_another_users_cipher_conflicts<U: UnitOfWork>(
    uow: &U,
) -> Result<(), DomainError> {
    let (alice, bob) = (alice()?, bob()?);
    let tx = uow.begin().await?;
    UserRepository::insert(&tx, &alice).await?;
    UserRepository::insert(&tx, &bob).await?;
    let revision = tx.bump_revision(alice.id()).await?;
    let secret = cipher(20, alice.id(), revision);
    CipherRepository::insert(&tx, &secret).await?;
    tx.commit().await?;

    let tx = uow.begin().await?;
    let hijack = Cipher::new(
        secret.id(),
        bob.id(),
        None,
        b"bob was here".to_vec(),
        tx.bump_revision(bob.id()).await?,
    );
    assert_eq!(
        CipherRepository::update(&tx, &hijack, revision).await,
        Err(DomainError::Conflict)
    );
    assert_eq!(
        CipherRepository::find(&tx, alice.id(), secret.id()).await?,
        Some(secret)
    );
    Ok(())
}

/// `changes_since` returns only the owner's changes after the given revision, tombstones
/// included, in increasing revision order.
pub async fn changes_since_returns_newer_changes_of_the_owner_in_order<U: UnitOfWork>(
    uow: &U,
) -> Result<(), DomainError> {
    let (alice, bob) = (alice()?, bob()?);
    let tx = uow.begin().await?;
    UserRepository::insert(&tx, &alice).await?;
    UserRepository::insert(&tx, &bob).await?;
    let since = tx.bump_revision(alice.id()).await?;
    let first = cipher(20, alice.id(), since);
    CipherRepository::insert(&tx, &first).await?;
    let second = cipher(21, alice.id(), tx.bump_revision(alice.id()).await?);
    CipherRepository::insert(&tx, &second).await?;
    let others = cipher(30, bob.id(), tx.bump_revision(bob.id()).await?);
    CipherRepository::insert(&tx, &others).await?;
    let mut tombstone = first.clone();
    tombstone.delete(tx.bump_revision(alice.id()).await?);
    CipherRepository::update(&tx, &tombstone, since).await?;
    tx.commit().await?;

    let tx = uow.begin().await?;
    assert_eq!(
        tx.changes_since(alice.id(), since).await?,
        vec![second.clone(), tombstone.clone()]
    );
    assert_eq!(
        tx.changes_since(alice.id(), Revision::ZERO).await?,
        vec![second, tombstone]
    );
    assert_eq!(
        tx.changes_since(bob.id(), Revision::ZERO).await?,
        vec![others]
    );
    Ok(())
}

/// Dropping a transaction without committing it discards its changes.
pub async fn dropped_transaction_is_rolled_back<U: UnitOfWork>(uow: &U) -> Result<(), DomainError> {
    let alice = alice()?;
    let tx = uow.begin().await?;
    UserRepository::insert(&tx, &alice).await?;
    drop(tx);

    let tx = uow.begin().await?;
    assert_eq!(tx.find_by_id(alice.id()).await?, None);
    Ok(())
}
