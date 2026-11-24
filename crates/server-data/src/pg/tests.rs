//! Tests on a real PostgreSQL (`TEST_DATABASE_URL`). Each test gets its own fresh database,
//! so tests run in parallel and never see each other's data.
//!
//! Without `TEST_DATABASE_URL` the tests are skipped locally, but they fail when `CI` is set:
//! a pipeline must never go green by testing nothing.

use std::collections::BTreeSet;
use std::path::Path;

use passguardian_server_domain::ports::StorageProbe;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, PgPool, Row};
use uuid::Uuid;

use super::PgStore;

/// A new empty database on the test server, or `None` when no server is configured.
async fn fresh_pool() -> Option<PgPool> {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        assert!(
            std::env::var_os("CI").is_none(),
            "TEST_DATABASE_URL must be set in CI"
        );
        eprintln!("skipped: TEST_DATABASE_URL is not set");
        return None;
    };
    let options: PgConnectOptions = url.parse().expect("TEST_DATABASE_URL is not a valid URL");
    let name = format!("pgtest_{}", Uuid::new_v4().simple());

    let mut admin = options
        .clone()
        .connect()
        .await
        .expect("cannot reach the test database");
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&mut admin)
        .await
        .expect("cannot create the test database");

    Some(
        PgPoolOptions::new()
            .max_connections(5)
            .connect_with(options.database(&name))
            .await
            .expect("cannot connect to the new database"),
    )
}

/// A migrated store on a fresh database.
async fn isolated_store() -> Option<PgStore> {
    let store = PgStore::from_pool(fresh_pool().await?);
    store.migrate().await.expect("migrations failed");
    Some(store)
}

mod contract {
    //! The same suite the in-memory fake passes (ADR 0007).
    use super::*;
    use passguardian_server_domain::testing::contract;

    macro_rules! on_postgres {
        ($($name:ident),* $(,)?) => {
            $(
                #[tokio::test]
                async fn $name() {
                    let Some(store) = isolated_store().await else { return };
                    contract::$name(&store).await.unwrap();
                }
            )*
        };
    }

    on_postgres!(
        inserted_user_is_found_by_id_and_email,
        user_with_taken_email_conflicts,
        unknown_user_is_not_found,
        user_revision_starts_at_zero_and_increments_by_one,
        inserted_device_is_found_by_its_owner_only,
        updated_device_stays_revoked,
        inserted_cipher_is_found_by_its_owner_only,
        cipher_update_at_expected_revision_succeeds,
        cipher_update_at_stale_revision_conflicts,
        cipher_update_of_another_users_cipher_conflicts,
        changes_since_returns_newer_changes_of_the_owner_in_order,
        dropped_transaction_is_rolled_back,
    );
}

mod migrations {
    use super::*;

    fn migrator() -> sqlx::migrate::Migrator {
        sqlx::migrate!("./migrations")
    }

    async fn table_names(pool: &PgPool) -> BTreeSet<String> {
        sqlx::query(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
        )
        .fetch_all(pool)
        .await
        .unwrap()
        .iter()
        .map(|row| row.get::<String, _>("table_name"))
        .collect()
    }

    #[tokio::test]
    async fn migrations_apply_on_empty_database() {
        let Some(pool) = fresh_pool().await else {
            return;
        };
        migrator().run(&pool).await.unwrap();
        let tables = table_names(&pool).await;
        for expected in ["users", "user_revision", "devices", "folders", "ciphers"] {
            assert!(tables.contains(expected), "missing table {expected}");
        }
    }

    #[tokio::test]
    async fn migrations_are_idempotent_when_rerun() {
        let Some(pool) = fresh_pool().await else {
            return;
        };
        migrator().run(&pool).await.unwrap();
        let before = table_names(&pool).await;
        migrator().run(&pool).await.unwrap();
        assert_eq!(table_names(&pool).await, before);
        let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(usize::try_from(applied).unwrap(), migrator().iter().count());
    }

    #[tokio::test]
    async fn applied_migration_checksums_match_files() {
        let Some(pool) = fresh_pool().await else {
            return;
        };
        migrator().run(&pool).await.unwrap();
        for migration in migrator().iter() {
            let stored: Vec<u8> =
                sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = $1")
                    .bind(migration.version)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(stored, migration.checksum.to_vec());
        }
        // A migration edited after being applied is refused, not silently re-run.
        sqlx::query("UPDATE _sqlx_migrations SET checksum = '\\x00'::bytea")
            .execute(&pool)
            .await
            .unwrap();
        assert!(migrator().run(&pool).await.is_err());
    }

    #[test]
    fn only_forward_migrations_exist() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut seen = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            assert!(
                !name.ends_with(".down.sql") && !name.ends_with(".up.sql"),
                "{name}: migrations are forward-only (name them NNNN_description.sql)"
            );
            assert_eq!(
                Path::new(&name).extension().and_then(|e| e.to_str()),
                Some("sql"),
                "{name} is not a migration"
            );
            seen += 1;
        }
        assert!(seen > 0);
    }

    /// Columns and indexes, as text.
    async fn schema_dump(pool: &PgPool) -> String {
        let mut lines: Vec<String> = sqlx::query(
            "SELECT table_name, column_name, data_type, is_nullable, column_default \
             FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name <> '_sqlx_migrations' \
             ORDER BY table_name, ordinal_position",
        )
        .fetch_all(pool)
        .await
        .unwrap()
        .iter()
        .map(|r| {
            format!(
                "column {}.{} {} nullable={} default={}",
                r.get::<String, _>("table_name"),
                r.get::<String, _>("column_name"),
                r.get::<String, _>("data_type"),
                r.get::<String, _>("is_nullable"),
                r.get::<Option<String>, _>("column_default")
                    .unwrap_or_default(),
            )
        })
        .collect();
        let indexes: Vec<String> = sqlx::query(
            "SELECT indexdef FROM pg_indexes \
             WHERE schemaname = 'public' AND tablename <> '_sqlx_migrations' ORDER BY indexdef",
        )
        .fetch_all(pool)
        .await
        .unwrap()
        .iter()
        .map(|r| format!("index {}", r.get::<String, _>("indexdef")))
        .collect();
        lines.extend(indexes);
        lines.push(String::new());
        lines.join("\n")
    }

    #[tokio::test]
    async fn schema_after_migrations_matches_snapshot() {
        let Some(pool) = fresh_pool().await else {
            return;
        };
        migrator().run(&pool).await.unwrap();
        let actual = schema_dump(&pool).await;
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/schema.txt");
        if std::env::var_os("UPDATE_SNAPSHOT").is_some() {
            std::fs::write(&path, &actual).unwrap();
        }
        let expected = std::fs::read_to_string(&path)
            .expect("snapshot missing: run the tests once with UPDATE_SNAPSHOT=1");
        assert_eq!(
            actual, expected,
            "the schema changed: review it, then refresh with UPDATE_SNAPSHOT=1"
        );
    }
}

mod behaviour {
    //! Rules that only make sense on a real database.
    use super::*;
    use passguardian_server_domain::ports::{
        CipherRepository, DeviceRepository, Transaction, UnitOfWork, UserRepository,
    };
    use passguardian_server_domain::{
        Cipher, CipherId, Device, DeviceId, DomainError, Email, Revision, User, UserId,
    };

    fn user(n: u128, email: &str) -> User {
        User::new(
            UserId::from_uuid(Uuid::from_u128(n)),
            Email::parse(email).unwrap(),
        )
        .with_credentials(vec![1, 2, 3], vec![4, 5])
    }

    #[tokio::test]
    async fn store_is_reachable() {
        let Some(store) = isolated_store().await else {
            return;
        };
        assert_eq!(store.ping().await, Ok(()));
    }

    #[tokio::test]
    async fn credentials_and_ciphertext_are_stored_byte_for_byte() {
        let Some(store) = isolated_store().await else {
            return;
        };
        let alice = user(1, "alice@example.com");
        let bytes: Vec<u8> = (0..=255).collect();
        let cipher = Cipher::new(
            CipherId::from_uuid(Uuid::from_u128(9)),
            alice.id(),
            None,
            bytes.clone(),
            Revision::new(1),
        );
        let tx = store.begin().await.unwrap();
        UserRepository::insert(&tx, &alice).await.unwrap();
        UserRepository::bump_revision(&tx, alice.id())
            .await
            .unwrap();
        CipherRepository::insert(&tx, &cipher).await.unwrap();
        tx.commit().await.unwrap();

        let tx = store.begin().await.unwrap();
        let found = UserRepository::find_by_id(&tx, alice.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.auth_hash(), &[1, 2, 3]);
        assert_eq!(found.key_envelope(), &[4, 5]);
        let stored = CipherRepository::find(&tx, alice.id(), cipher.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.data(), bytes.as_slice());
    }

    #[tokio::test]
    async fn tombstones_roundtrip() {
        let Some(store) = isolated_store().await else {
            return;
        };
        let alice = user(1, "alice@example.com");
        let mut cipher = Cipher::new(
            CipherId::from_uuid(Uuid::from_u128(9)),
            alice.id(),
            None,
            vec![1],
            Revision::new(1),
        );
        let tx = store.begin().await.unwrap();
        UserRepository::insert(&tx, &alice).await.unwrap();
        CipherRepository::insert(&tx, &cipher).await.unwrap();
        cipher.delete(Revision::new(2));
        CipherRepository::update(&tx, &cipher, Revision::new(1))
            .await
            .unwrap();
        let stored = CipherRepository::find(&tx, alice.id(), cipher.id())
            .await
            .unwrap()
            .unwrap();
        assert!(stored.is_deleted());
        assert_eq!(stored, cipher);
    }

    #[tokio::test]
    async fn concurrent_updates_with_same_revision_only_one_wins() {
        let Some(store) = isolated_store().await else {
            return;
        };
        let alice = user(1, "alice@example.com");
        let id = CipherId::from_uuid(Uuid::from_u128(9));
        let base = Cipher::new(id, alice.id(), None, vec![0], Revision::new(1));
        let tx = store.begin().await.unwrap();
        UserRepository::insert(&tx, &alice).await.unwrap();
        CipherRepository::insert(&tx, &base).await.unwrap();
        tx.commit().await.unwrap();

        let attempt = |value: u8| {
            let store = store.clone();
            let owner = alice.id();
            async move {
                let tx = store.begin().await?;
                let mut cipher = CipherRepository::find(&tx, owner, id).await?.unwrap();
                cipher.update(None, vec![value], Revision::new(2));
                CipherRepository::update(&tx, &cipher, Revision::new(1)).await?;
                tx.commit().await
            }
        };
        let (first, second) = tokio::join!(attempt(1), attempt(2));
        let winners = [&first, &second].iter().filter(|r| r.is_ok()).count();
        assert_eq!(winners, 1, "{first:?} / {second:?}");
    }

    #[tokio::test]
    async fn user_revision_is_monotonic_under_concurrency() {
        let Some(store) = isolated_store().await else {
            return;
        };
        let alice = user(1, "alice@example.com");
        let tx = store.begin().await.unwrap();
        UserRepository::insert(&tx, &alice).await.unwrap();
        tx.commit().await.unwrap();

        let bump = || {
            let store = store.clone();
            let owner = alice.id();
            async move {
                let tx = store.begin().await.unwrap();
                let revision = UserRepository::bump_revision(&tx, owner).await.unwrap();
                tx.commit().await.unwrap();
                revision.get()
            }
        };
        let handles: Vec<_> = (0..20).map(|_| tokio::spawn(bump())).collect();
        let mut revisions = Vec::new();
        for handle in handles {
            revisions.push(handle.await.unwrap());
        }
        revisions.sort_unstable();
        assert_eq!(revisions, (1..=20).collect::<Vec<u64>>());
    }

    #[tokio::test]
    async fn unique_email_constraint_maps_to_domain_conflict() {
        let Some(store) = isolated_store().await else {
            return;
        };
        let tx = store.begin().await.unwrap();
        UserRepository::insert(&tx, &user(1, "alice@example.com"))
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let tx = store.begin().await.unwrap();
        assert_eq!(
            UserRepository::insert(&tx, &user(2, "alice@example.com")).await,
            Err(DomainError::Conflict)
        );
    }

    #[tokio::test]
    async fn device_of_unknown_user_is_a_conflict() {
        let Some(store) = isolated_store().await else {
            return;
        };
        let device = Device::new(
            DeviceId::from_uuid(Uuid::from_u128(5)),
            UserId::from_uuid(Uuid::from_u128(404)),
            "laptop",
        )
        .unwrap();
        let tx = store.begin().await.unwrap();
        assert_eq!(
            DeviceRepository::insert(&tx, &device).await,
            Err(DomainError::Conflict)
        );
    }
}
