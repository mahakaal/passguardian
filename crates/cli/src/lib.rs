//! PassGuardian command-line client.
//!
//! Everything secret happens here, on the client: the master password never leaves the
//! process, the server only receives the login key and ciphertext.

pub mod api;
pub mod app;
pub mod error;
pub mod session;

pub use app::{Cli, Entry, Item};
pub use error::CliError;
