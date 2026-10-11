//! PassGuardian server domain.
//!
//! Holds the application logic and the *ports* (traits) that the other layers implement.
//! It knows nothing about HTTP or the database. Dependencies point towards this crate,
//! never away from it.

pub mod error;
pub mod health;
pub mod ports;

pub use error::DomainError;
pub use health::{HealthService, HealthStatus};
