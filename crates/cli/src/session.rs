//! The session file: what this device remembers between commands. Never the master password
//! and never any decrypted key.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::CliError;

/// Persistent state of a logged-in device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Base URL of the server.
    pub server: String,
    /// Account email.
    pub email: String,
    /// User identifier.
    pub user_id: String,
    /// This device's identifier.
    pub device_id: String,
    /// Short-lived token.
    pub access_token: String,
    /// Long-lived token.
    pub refresh_token: String,
    /// The key envelope (a vault document without items), base64.
    pub key_envelope: String,
}

fn file(home: &Path) -> PathBuf {
    home.join("session.json")
}

impl Session {
    /// Reads the session of `home`, if any.
    pub fn load(home: &Path) -> Result<Self, CliError> {
        let text = fs::read_to_string(file(home)).map_err(|_| CliError::NotLoggedIn)?;
        serde_json::from_str(&text).map_err(|_| CliError::NotLoggedIn)
    }

    /// Writes the session with owner-only permissions.
    pub fn save(&self, home: &Path) -> Result<(), CliError> {
        fs::create_dir_all(home)?;
        let text = serde_json::to_string_pretty(self).map_err(|e| CliError::Io(e.to_string()))?;
        let path = file(home);
        write_private(&path, text.as_bytes())
    }

    /// Forgets the session.
    pub fn remove(home: &Path) -> Result<(), CliError> {
        match fs::remove_file(file(home)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    fs::write(path, bytes)?;
    Ok(())
}

/// Where the session lives by default: `$PASSGUARDIAN_HOME`, else the XDG config directory.
#[must_use]
pub fn default_home() -> PathBuf {
    if let Some(dir) = std::env::var_os("PASSGUARDIAN_HOME") {
        return PathBuf::from(dir);
    }
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(dir).join("passguardian");
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    home.join(".config").join("passguardian")
}
