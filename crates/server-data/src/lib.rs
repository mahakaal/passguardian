//! PassGuardian server data layer.
//!
//! Implements the traits defined in `passguardian-server-domain::ports`.
//! Rule: database types (rows, sqlx errors) never leave this crate;
//! they are always mapped to domain entities and errors.
//!
//! Roadmap: Sprint 3 adds PostgreSQL and migrations.

use passguardian_server_domain::{ports::StorageProbe, DomainError};

/// Placeholder storage that is always reachable. Stands in until PostgreSQL arrives (Sprint 3).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopStorage;

impl StorageProbe for NoopStorage {
    async fn ping(&self) -> Result<(), DomainError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_storage_is_always_up() {
        assert_eq!(NoopStorage.ping().await, Ok(()));
    }
}
