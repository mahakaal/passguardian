//! Domain errors. The API layer maps them to HTTP status codes.

use thiserror::Error;

/// Domain error, independent of transport and storage.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainError {
    /// A required dependency (for example storage) is unreachable.
    #[error("service temporarily unavailable")]
    Unavailable,
    /// A text could not be parsed as an identifier.
    #[error("invalid identifier")]
    InvalidId,
    /// A text is not an acceptable email address.
    #[error("invalid email address")]
    InvalidEmail,
    /// A name is empty, too long or otherwise not acceptable.
    #[error("invalid name")]
    InvalidName,
    /// The change clashes with existing data: a duplicate, or a stale revision.
    #[error("conflict")]
    Conflict,
    /// A revision counter cannot be incremented any further.
    #[error("revision overflow")]
    RevisionOverflow,
}
