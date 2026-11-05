//! PassGuardian server domain.
//!
//! Holds the application logic and the *ports* (traits) that the other layers implement.
//! It knows nothing about HTTP or the database. Dependencies point towards this crate,
//! never away from it.

pub mod email;
pub mod entities;
pub mod error;
pub mod health;
pub mod ids;
pub mod ports;
pub mod revision;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod time;

pub use email::Email;
pub use entities::{Cipher, Device, Folder, User};
pub use error::DomainError;
pub use health::{HealthService, HealthStatus};
pub use ids::{CipherId, DeviceId, FolderId, UserId};
pub use revision::Revision;
pub use time::Timestamp;
