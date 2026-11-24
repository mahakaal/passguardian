//! Test support: in-memory fakes of the ports and the contract test suite.
//!
//! Compiled for this crate's tests, and for other crates with the `testing` feature
//! (`server-data` runs the same contract suite against PostgreSQL).

pub mod contract;
mod memory;

pub use memory::{InMemoryStore, InMemoryTransaction};

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use crate::ports::{Clock, IdGenerator};
use crate::Timestamp;

/// A clock that always returns the same time.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(Timestamp);

impl FixedClock {
    /// Creates a clock stopped at `now`.
    #[must_use]
    pub fn new(now: Timestamp) -> Self {
        Self(now)
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}

/// A clock that only moves when told to. Clones share the same time.
#[derive(Debug, Clone)]
pub struct ManualClock(Arc<AtomicI64>);

impl ManualClock {
    /// Creates a clock set to `now`.
    #[must_use]
    pub fn new(now: Timestamp) -> Self {
        Self(Arc::new(AtomicI64::new(now.as_unix_seconds())))
    }

    /// Moves the clock forward.
    pub fn advance(&self, seconds: i64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_seconds(self.0.load(Ordering::SeqCst))
    }
}

/// Hands out the UUIDs 1, 2, 3, ... (starting above the small numbers tests use by hand).
#[derive(Debug, Default)]
pub struct SequentialIds(AtomicU64);

impl SequentialIds {
    /// Creates a generator starting at 1000.
    #[must_use]
    pub fn new() -> Self {
        Self(AtomicU64::new(1000))
    }
}

impl IdGenerator for SequentialIds {
    fn new_uuid(&self) -> uuid::Uuid {
        uuid::Uuid::from_u128(u128::from(self.0.fetch_add(1, Ordering::SeqCst)))
    }
}

/// Generates one `#[tokio::test]` per contract test, each on a fresh store built by the
/// given expression (which may `.await`). The calling crate needs `tokio` as a
/// dev-dependency.
///
/// ```ignore
/// mod contract {
///     passguardian_server_domain::repository_contract_tests!(PgStore::isolated().await);
/// }
/// ```
#[macro_export]
macro_rules! repository_contract_tests {
    ($new_store:expr) => {
        $crate::repository_contract_tests!(@tests $new_store;
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
    };
    (@tests $new_store:expr; $($name:ident),* $(,)?) => {
        $(
            #[tokio::test]
            async fn $name() {
                let store = $new_store;
                $crate::testing::contract::$name(&store).await.unwrap();
            }
        )*
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_does_not_move() {
        let clock = FixedClock::new(Timestamp::from_unix_seconds(42));
        assert_eq!(clock.now(), clock.now());
        assert_eq!(clock.now().as_unix_seconds(), 42);
    }

    mod in_memory_contract {
        crate::repository_contract_tests!(crate::testing::InMemoryStore::new());
    }
}
