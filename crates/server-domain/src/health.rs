//! Minimal use case that demonstrates the api → domain → data flow.

use crate::{ports::StorageProbe, DomainError};

/// Health status reported by the domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// The server is ready.
    Ready,
}

/// Health service, generic over storage to avoid dynamic dispatch.
#[derive(Debug, Clone)]
pub struct HealthService<S> {
    storage: S,
}

impl<S: StorageProbe> HealthService<S> {
    /// Creates the service with the storage to probe.
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Checks that the dependencies are reachable.
    pub async fn check(&self) -> Result<HealthStatus, DomainError> {
        self.storage.ping().await?;
        Ok(HealthStatus::Ready)
    }
}

#[cfg(test)]
mod tests {
    use std::future::{ready, Future};

    use super::*;

    struct Up;
    struct Down;

    impl StorageProbe for Up {
        fn ping(&self) -> impl Future<Output = Result<(), DomainError>> + Send {
            ready(Ok(()))
        }
    }

    impl StorageProbe for Down {
        fn ping(&self) -> impl Future<Output = Result<(), DomainError>> + Send {
            ready(Err(DomainError::Unavailable))
        }
    }

    #[tokio::test]
    async fn ready_when_storage_is_up() {
        let svc = HealthService::new(Up);
        assert_eq!(svc.check().await, Ok(HealthStatus::Ready));
    }

    #[tokio::test]
    async fn unavailable_when_storage_is_down() {
        let svc = HealthService::new(Down);
        assert_eq!(svc.check().await, Err(DomainError::Unavailable));
    }
}
