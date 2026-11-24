//! PostgreSQL implementation of the storage ports.
//!
//! One [`PgTransaction`] wraps one database transaction; dropping it without committing rolls
//! it back (sqlx does that for us). Every query that touches user data names the owner.
//! `sqlx` types never leave this module: errors are mapped to [`DomainError`].

use passguardian_server_domain::ports::{
    CipherRepository, DeviceRepository, StorageProbe, Transaction, UnitOfWork, UserRepository,
};
use passguardian_server_domain::{
    Cipher, CipherId, Device, DeviceId, DomainError, Email, FolderId, Revision, User, UserId,
};
use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::{PgPool, Postgres, Row};
use tokio::sync::Mutex;
use uuid::Uuid;

/// PostgreSQL error codes that mean "this clashes with existing data".
const UNIQUE_VIOLATION: &str = "23505";
const FOREIGN_KEY_VIOLATION: &str = "23503";

fn map_error(error: &sqlx::Error) -> DomainError {
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
    {
        Some(code) if code == UNIQUE_VIOLATION || code == FOREIGN_KEY_VIOLATION => {
            DomainError::Conflict
        }
        _ => DomainError::Unavailable,
    }
}

fn revision_to_db(revision: Revision) -> Result<i64, DomainError> {
    i64::try_from(revision.get()).map_err(|_| DomainError::RevisionOverflow)
}

fn revision_from_db(value: i64) -> Result<Revision, DomainError> {
    u64::try_from(value)
        .map(Revision::new)
        .map_err(|_| DomainError::Unavailable)
}

/// Data that fails the domain's own validation means the database is damaged.
fn corrupt<E>(_: E) -> DomainError {
    DomainError::Unavailable
}

/// The database, as seen by the domain.
#[derive(Debug, Clone)]
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    /// Connects to the database at `url`.
    pub async fn connect(url: &str) -> Result<Self, DomainError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await
            .map_err(|e| map_error(&e))?;
        Ok(Self { pool })
    }

    /// Wraps an existing connection pool.
    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Applies the pending migrations. Safe to run on every start.
    pub async fn migrate(&self) -> Result<(), DomainError> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|_| DomainError::Unavailable)
    }
}

impl StorageProbe for PgStore {
    async fn ping(&self) -> Result<(), DomainError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|e| map_error(&e))
    }
}

impl UnitOfWork for PgStore {
    type Tx = PgTransaction;

    async fn begin(&self) -> Result<PgTransaction, DomainError> {
        let tx = self.pool.begin().await.map_err(|e| map_error(&e))?;
        Ok(PgTransaction {
            tx: Mutex::new(Some(tx)),
        })
    }
}

/// A database transaction. The repositories take `&self`, so the connection sits behind a lock.
#[derive(Debug)]
pub struct PgTransaction {
    tx: Mutex<Option<sqlx::Transaction<'static, Postgres>>>,
}

/// Runs `$query` (a `sqlx` query) on the transaction's connection with `$method`.
macro_rules! run {
    ($self:ident, $method:ident, $query:expr) => {{
        let mut guard = $self.tx.lock().await;
        let tx = guard.as_mut().ok_or(DomainError::Unavailable)?;
        $query.$method(&mut **tx).await.map_err(|e| map_error(&e))
    }};
}

impl Transaction for PgTransaction {
    async fn commit(self) -> Result<(), DomainError> {
        let tx = self.tx.into_inner().ok_or(DomainError::Unavailable)?;
        tx.commit().await.map_err(|e| map_error(&e))
    }
}

fn user_from_row(row: &PgRow) -> Result<User, DomainError> {
    let id: Uuid = row.try_get("id").map_err(|e| map_error(&e))?;
    let email: String = row.try_get("email").map_err(|e| map_error(&e))?;
    let auth_hash: Vec<u8> = row.try_get("auth_hash").map_err(|e| map_error(&e))?;
    let key_envelope: Vec<u8> = row.try_get("key_envelope").map_err(|e| map_error(&e))?;
    Ok(User::new(
        UserId::from_uuid(id),
        Email::parse(&email).map_err(corrupt)?,
    )
    .with_credentials(auth_hash, key_envelope))
}

fn device_from_row(row: &PgRow) -> Result<Device, DomainError> {
    let id: Uuid = row.try_get("id").map_err(|e| map_error(&e))?;
    let user_id: Uuid = row.try_get("user_id").map_err(|e| map_error(&e))?;
    let name: String = row.try_get("name").map_err(|e| map_error(&e))?;
    let revoked: bool = row.try_get("revoked").map_err(|e| map_error(&e))?;
    let mut device =
        Device::new(DeviceId::from_uuid(id), UserId::from_uuid(user_id), &name).map_err(corrupt)?;
    if revoked {
        device.revoke();
    }
    Ok(device)
}

fn cipher_from_row(row: &PgRow) -> Result<Cipher, DomainError> {
    let id: Uuid = row.try_get("id").map_err(|e| map_error(&e))?;
    let user_id: Uuid = row.try_get("user_id").map_err(|e| map_error(&e))?;
    let folder_id: Option<Uuid> = row.try_get("folder_id").map_err(|e| map_error(&e))?;
    let data: Vec<u8> = row.try_get("data").map_err(|e| map_error(&e))?;
    let revision = revision_from_db(row.try_get("revision").map_err(|e| map_error(&e))?)?;
    let deleted: bool = row.try_get("deleted").map_err(|e| map_error(&e))?;
    let mut cipher = Cipher::new(
        CipherId::from_uuid(id),
        UserId::from_uuid(user_id),
        folder_id.map(FolderId::from_uuid),
        data,
        revision,
    );
    if deleted {
        cipher.delete(revision);
    }
    Ok(cipher)
}

impl UserRepository for PgTransaction {
    async fn insert(&self, user: &User) -> Result<(), DomainError> {
        run!(
            self,
            execute,
            sqlx::query(
                "INSERT INTO users (id, email, auth_hash, key_envelope) VALUES ($1, $2, $3, $4)"
            )
            .bind(user.id().as_uuid())
            .bind(user.email().as_str())
            .bind(user.auth_hash())
            .bind(user.key_envelope())
        )
        .map(|_| ())
    }

    async fn find_by_id(&self, id: UserId) -> Result<Option<User>, DomainError> {
        run!(
            self,
            fetch_optional,
            sqlx::query("SELECT id, email, auth_hash, key_envelope FROM users WHERE id = $1")
                .bind(id.as_uuid())
        )?
        .as_ref()
        .map(user_from_row)
        .transpose()
    }

    async fn find_by_email(&self, email: &Email) -> Result<Option<User>, DomainError> {
        run!(
            self,
            fetch_optional,
            sqlx::query("SELECT id, email, auth_hash, key_envelope FROM users WHERE email = $1")
                .bind(email.as_str())
        )?
        .as_ref()
        .map(user_from_row)
        .transpose()
    }

    async fn revision(&self, id: UserId) -> Result<Revision, DomainError> {
        let row = run!(
            self,
            fetch_optional,
            sqlx::query("SELECT revision FROM user_revision WHERE user_id = $1").bind(id.as_uuid())
        )?;
        match row {
            Some(row) => revision_from_db(row.try_get("revision").map_err(|e| map_error(&e))?),
            None => Ok(Revision::ZERO),
        }
    }

    async fn bump_revision(&self, id: UserId) -> Result<Revision, DomainError> {
        // The row lock taken by the upsert serialises concurrent writers of the same user
        // until their transaction ends, so revisions are strictly increasing.
        let row = run!(
            self,
            fetch_one,
            sqlx::query(
                "INSERT INTO user_revision (user_id, revision) VALUES ($1, 1) \
                 ON CONFLICT (user_id) DO UPDATE SET revision = user_revision.revision + 1 \
                 RETURNING revision"
            )
            .bind(id.as_uuid())
        )?;
        revision_from_db(row.try_get("revision").map_err(|e| map_error(&e))?)
    }
}

impl DeviceRepository for PgTransaction {
    async fn insert(&self, device: &Device) -> Result<(), DomainError> {
        run!(
            self,
            execute,
            sqlx::query("INSERT INTO devices (id, user_id, name, revoked) VALUES ($1, $2, $3, $4)")
                .bind(device.id().as_uuid())
                .bind(device.user_id().as_uuid())
                .bind(device.name())
                .bind(device.is_revoked())
        )
        .map(|_| ())
    }

    async fn find(&self, user_id: UserId, id: DeviceId) -> Result<Option<Device>, DomainError> {
        run!(
            self,
            fetch_optional,
            sqlx::query(
                "SELECT id, user_id, name, revoked FROM devices WHERE id = $1 AND user_id = $2"
            )
            .bind(id.as_uuid())
            .bind(user_id.as_uuid())
        )?
        .as_ref()
        .map(device_from_row)
        .transpose()
    }

    async fn update(&self, device: &Device) -> Result<(), DomainError> {
        let done = run!(
            self,
            execute,
            sqlx::query(
                "UPDATE devices SET name = $3, revoked = $4 WHERE id = $1 AND user_id = $2"
            )
            .bind(device.id().as_uuid())
            .bind(device.user_id().as_uuid())
            .bind(device.name())
            .bind(device.is_revoked())
        )?;
        if done.rows_affected() == 1 {
            Ok(())
        } else {
            Err(DomainError::Conflict)
        }
    }
}

impl CipherRepository for PgTransaction {
    async fn insert(&self, cipher: &Cipher) -> Result<(), DomainError> {
        run!(
            self,
            execute,
            sqlx::query(
                "INSERT INTO ciphers (id, user_id, folder_id, data, revision, deleted) \
                 VALUES ($1, $2, $3, $4, $5, $6)"
            )
            .bind(cipher.id().as_uuid())
            .bind(cipher.user_id().as_uuid())
            .bind(cipher.folder_id().map(|f| f.as_uuid()))
            .bind(cipher.data())
            .bind(revision_to_db(cipher.revision())?)
            .bind(cipher.is_deleted())
        )
        .map(|_| ())
    }

    async fn find(&self, user_id: UserId, id: CipherId) -> Result<Option<Cipher>, DomainError> {
        run!(
            self,
            fetch_optional,
            sqlx::query(
                "SELECT id, user_id, folder_id, data, revision, deleted FROM ciphers \
                 WHERE id = $1 AND user_id = $2"
            )
            .bind(id.as_uuid())
            .bind(user_id.as_uuid())
        )?
        .as_ref()
        .map(cipher_from_row)
        .transpose()
    }

    async fn update(&self, cipher: &Cipher, expected: Revision) -> Result<(), DomainError> {
        let done = run!(
            self,
            execute,
            sqlx::query(
                "UPDATE ciphers SET folder_id = $3, data = $4, revision = $5, deleted = $6 \
                 WHERE id = $1 AND user_id = $2 AND revision = $7"
            )
            .bind(cipher.id().as_uuid())
            .bind(cipher.user_id().as_uuid())
            .bind(cipher.folder_id().map(|f| f.as_uuid()))
            .bind(cipher.data())
            .bind(revision_to_db(cipher.revision())?)
            .bind(cipher.is_deleted())
            .bind(revision_to_db(expected)?)
        )?;
        if done.rows_affected() == 1 {
            Ok(())
        } else {
            Err(DomainError::Conflict)
        }
    }

    async fn changes_since(
        &self,
        user_id: UserId,
        since: Revision,
    ) -> Result<Vec<Cipher>, DomainError> {
        run!(
            self,
            fetch_all,
            sqlx::query(
                "SELECT id, user_id, folder_id, data, revision, deleted FROM ciphers \
                 WHERE user_id = $1 AND revision > $2 ORDER BY revision"
            )
            .bind(user_id.as_uuid())
            .bind(revision_to_db(since)?)
        )?
        .iter()
        .map(cipher_from_row)
        .collect()
    }
}

#[cfg(test)]
mod tests;
