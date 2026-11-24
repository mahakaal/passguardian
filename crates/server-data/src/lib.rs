//! PassGuardian server data layer.
//!
//! Implements the traits defined in `passguardian-server-domain::ports` on PostgreSQL.
//! Rule: database types (rows, sqlx errors) never leave this crate;
//! they are always mapped to domain entities and errors.

mod pg;

pub use pg::{PgStore, PgTransaction};
