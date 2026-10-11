//! Domain errors. The API layer maps them to HTTP status codes.

use thiserror::Error;

/// Domain error, independent of transport and storage.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainError {
    /// A required dependency (for example storage) is unreachable.
    #[error("service temporarily unavailable")]
    Unavailable,
}
