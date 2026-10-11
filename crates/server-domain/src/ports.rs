//! Ports: interfaces the domain requires from the outer layers.
//!
//! Implementations live in `server-data` (storage) or in the binary (everything else).
//! In Sprint 2 this module gains `UserRepository`, `DeviceRepository`,
//! `CipherRepository` and `Clock`.

use std::future::Future;

use crate::DomainError;

/// Checks that storage is responding. Used by the health endpoint.
pub trait StorageProbe: Send + Sync {
    /// Returns `Ok(())` if storage is reachable.
    fn ping(&self) -> impl Future<Output = Result<(), DomainError>> + Send;
}
