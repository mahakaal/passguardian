//! Errors of the CLI. Messages never contain secrets.

use thiserror::Error;

/// Everything that can go wrong in a command.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CliError {
    /// The server answered with an error.
    #[error("the server refused the request ({status}): {message}")]
    Server {
        /// HTTP status.
        status: u16,
        /// Message from the server's error body.
        message: String,
    },
    /// The server could not be reached or sent something unreadable.
    #[error("cannot talk to the server: {0}")]
    Network(String),
    /// Not logged in on this device.
    #[error("not logged in: run `passguardian login` first")]
    NotLoggedIn,
    /// The master password is wrong, or the vault data was modified.
    #[error("wrong master password or damaged vault data")]
    WrongPassword,
    /// The vault was created with settings this build does not accept.
    #[error("the account uses key derivation settings this client does not accept")]
    UnsupportedEnvelope,
    /// No item matches the given name or identifier.
    #[error("no item matches '{0}'")]
    ItemNotFound(String),
    /// More than one item matches the given name.
    #[error("'{0}' matches more than one item: use the identifier")]
    Ambiguous(String),
    /// Bad input from the user.
    #[error("{0}")]
    Input(String),
    /// A cryptographic failure.
    #[error("cryptographic failure: {0}")]
    Crypto(String),
    /// A local file problem.
    #[error("local file error: {0}")]
    Io(String),
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<passguardian_core::CryptoError> for CliError {
    fn from(error: passguardian_core::CryptoError) -> Self {
        Self::Crypto(error.to_string())
    }
}
