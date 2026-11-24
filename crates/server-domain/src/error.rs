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
    /// Wrong or unknown credentials, or a revoked device. Deliberately one case, so a caller
    /// cannot tell an unknown account from a wrong secret.
    #[error("invalid credentials")]
    InvalidCredentials,
    /// Too many failed attempts: try again later.
    #[error("too many attempts")]
    RateLimited,
    /// The resource does not exist, or belongs to somebody else.
    #[error("not found")]
    NotFound,
    /// A value that is not an email or a name is malformed (for example a key of the wrong size).
    #[error("invalid input")]
    InvalidInput,
    /// The change clashes with existing data: a duplicate, or a stale revision.
    #[error("conflict")]
    Conflict,
    /// A revision counter cannot be incremented any further.
    #[error("revision overflow")]
    RevisionOverflow,
}
