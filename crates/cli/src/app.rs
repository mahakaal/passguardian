//! The commands. Every function takes what it needs explicitly (home directory, master
//! password) so the end-to-end test can drive them like several devices.

use std::fmt;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine};
use passguardian_core::{
    decrypt_item, derive_master_key, encrypt_item, login_salt, EncryptedItem, KdfParams, MasterKey,
    VaultDocument, VaultKey,
};
use passguardian_proto::{CreateCipherRequest, LoginRequest, RegisterRequest, SessionResponse};
use serde::{Deserialize, Serialize};

use crate::api::{is_unauthorized, ApiClient};
use crate::error::CliError;
use crate::session::Session;

/// What a vault entry holds. This is the plaintext that gets encrypted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    /// Display name.
    pub name: String,
    /// User name or email used on the site.
    #[serde(default)]
    pub username: String,
    /// The secret.
    #[serde(default)]
    pub password: String,
    /// Address of the site.
    #[serde(default)]
    pub url: String,
    /// Free notes.
    #[serde(default)]
    pub notes: String,
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("name", &self.name)
            .field("password", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A decrypted item with its place on the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Identifier.
    pub id: String,
    /// Revision at which it last changed.
    pub revision: u64,
    /// The content.
    pub item: Item,
}

/// A device's view of the CLI: where it keeps its session and which KDF cost it uses.
#[derive(Debug, Clone)]
pub struct Cli {
    home: PathBuf,
    kdf: KdfParams,
}

impl Cli {
    /// A CLI keeping its state in `home`, with the standard key derivation cost.
    #[must_use]
    pub fn new(home: PathBuf) -> Self {
        Self {
            home,
            kdf: KdfParams::DEFAULT,
        }
    }

    /// Replaces the key derivation cost. Only tests lower it: the server cannot tell, but a
    /// real account must use [`KdfParams::DEFAULT`] (see ADR 0009, limitation 1).
    #[must_use]
    pub fn with_kdf(mut self, kdf: KdfParams) -> Self {
        self.kdf = kdf;
        self
    }

    fn master_key(&self, email: &str, password: &str) -> Result<MasterKey, CliError> {
        Ok(derive_master_key(
            password.as_bytes(),
            &login_salt(email),
            &self.kdf,
        )?)
    }

    /// Creates an account on `server` and stores the session of this device.
    pub fn register(
        &self,
        server: &str,
        email: &str,
        password: &str,
        device_name: &str,
    ) -> Result<(), CliError> {
        if password.is_empty() {
            return Err(CliError::Input(
                "the master password cannot be empty".into(),
            ));
        }
        let master = self.master_key(email, password)?;
        let vault_key = VaultKey::generate()?;
        let wrapped = vault_key.wrap(&master)?;
        let envelope = VaultDocument::new(self.kdf, login_salt(email).to_vec(), wrapped, vec![])
            .to_json()
            .map_err(|e| CliError::Crypto(e.to_string()))?;
        let auth = master.auth_key()?;
        let response = ApiClient::new(server).register(&RegisterRequest {
            email: email.to_owned(),
            auth_key: auth.as_bytes().to_vec(),
            key_envelope: envelope.into_bytes(),
            device_name: device_name.to_owned(),
        })?;
        self.store_session(server, email, response)
    }

    /// Logs this device in to an existing account.
    pub fn login(
        &self,
        server: &str,
        email: &str,
        password: &str,
        device_name: &str,
    ) -> Result<(), CliError> {
        let master = self.master_key(email, password)?;
        let auth = master.auth_key()?;
        let response = ApiClient::new(server).login(&LoginRequest {
            email: email.to_owned(),
            auth_key: auth.as_bytes().to_vec(),
            device_name: device_name.to_owned(),
        })?;
        // The password was right for the server; make sure the envelope is usable too.
        self.open_envelope(&response.key_envelope, &master)?;
        self.store_session(server, email, response)
    }

    /// Forgets the session of this device.
    pub fn logout(&self) -> Result<(), CliError> {
        Session::remove(&self.home)
    }

    fn store_session(
        &self,
        server: &str,
        email: &str,
        response: SessionResponse,
    ) -> Result<(), CliError> {
        Session {
            server: server.to_owned(),
            email: email.to_owned(),
            user_id: response.user_id,
            device_id: response.device_id,
            access_token: response.access_token,
            refresh_token: response.refresh_token,
            key_envelope: STANDARD.encode(&response.key_envelope),
        }
        .save(&self.home)
    }

    fn open_envelope(&self, envelope: &[u8], master: &MasterKey) -> Result<VaultKey, CliError> {
        let text = std::str::from_utf8(envelope).map_err(|_| CliError::UnsupportedEnvelope)?;
        let document = VaultDocument::from_json(text).map_err(|_| CliError::UnsupportedEnvelope)?;
        if document.kdf != self.kdf {
            return Err(CliError::UnsupportedEnvelope);
        }
        VaultKey::unwrap(&document.wrapped_vault_key, master).map_err(|_| CliError::WrongPassword)
    }

    /// Loads the session and unlocks the vault key with the master password.
    fn unlock(&self, password: &str) -> Result<(Session, VaultKey), CliError> {
        let session = Session::load(&self.home)?;
        let master = self.master_key(&session.email, password)?;
        let envelope = STANDARD
            .decode(&session.key_envelope)
            .map_err(|_| CliError::NotLoggedIn)?;
        let key = self.open_envelope(&envelope, &master)?;
        Ok((session, key))
    }

    /// Runs `call` with the access token; on a 401 refreshes it once and retries.
    fn authorized<T>(
        &self,
        session: &mut Session,
        call: impl Fn(&ApiClient, &str) -> Result<T, CliError>,
    ) -> Result<T, CliError> {
        let client = ApiClient::new(&session.server);
        match call(&client, &session.access_token) {
            Err(error) if is_unauthorized(&error) => {
                session.access_token = client.refresh(&session.refresh_token)?.access_token;
                session.save(&self.home)?;
                call(&client, &session.access_token)
            }
            other => other,
        }
    }

    fn fetch(&self, session: &mut Session, key: &VaultKey) -> Result<(u64, Vec<Entry>), CliError> {
        let sync = self.authorized(session, |api, token| api.sync(token, 0))?;
        let mut entries = Vec::new();
        for cipher in sync.changes.into_iter().filter(|c| !c.deleted) {
            let plain = decrypt_item(
                key,
                cipher.id.as_bytes(),
                &EncryptedItem::from_bytes(cipher.data),
            )
            .map_err(|_| CliError::Crypto("an item could not be decrypted".into()))?;
            let item: Item = serde_json::from_slice(&plain)
                .map_err(|_| CliError::Crypto("an item has an unknown shape".into()))?;
            entries.push(Entry {
                id: cipher.id,
                revision: cipher.revision,
                item,
            });
        }
        entries.sort_by(|a, b| {
            a.item
                .name
                .to_lowercase()
                .cmp(&b.item.name.to_lowercase())
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok((sync.revision, entries))
    }

    /// Adds an item and returns its identifier.
    pub fn add(&self, password: &str, item: &Item) -> Result<String, CliError> {
        if item.name.trim().is_empty() {
            return Err(CliError::Input("the item needs a name".into()));
        }
        let (mut session, key) = self.unlock(password)?;
        let id = uuid::Uuid::new_v4().to_string();
        let plain = serde_json::to_vec(item).map_err(|e| CliError::Crypto(e.to_string()))?;
        let sealed = encrypt_item(&key, id.as_bytes(), &plain)?;
        let request = CreateCipherRequest {
            id: id.clone(),
            folder_id: None,
            data: sealed.as_bytes().to_vec(),
        };
        self.authorized(&mut session, |api, token| {
            api.create_cipher(token, &request)
        })?;
        Ok(id)
    }

    /// Every live item, sorted by name.
    pub fn list(&self, password: &str) -> Result<Vec<Entry>, CliError> {
        let (mut session, key) = self.unlock(password)?;
        Ok(self.fetch(&mut session, &key)?.1)
    }

    /// The item whose identifier or (case-insensitive) name is `query`.
    pub fn get(&self, password: &str, query: &str) -> Result<Entry, CliError> {
        find(self.list(password)?, query)
    }

    /// Deletes the item matching `query`; the server keeps a tombstone for other devices.
    pub fn delete(&self, password: &str, query: &str) -> Result<String, CliError> {
        let (mut session, key) = self.unlock(password)?;
        let entry = find(self.fetch(&mut session, &key)?.1, query)?;
        self.authorized(&mut session, |api, token| {
            api.delete_cipher(token, &entry.id, entry.revision)
        })?;
        Ok(entry.id)
    }

    /// Number of live items and the vault revision, as the server reports them.
    pub fn status(&self, password: &str) -> Result<(u64, usize), CliError> {
        let (mut session, key) = self.unlock(password)?;
        let (revision, entries) = self.fetch(&mut session, &key)?;
        Ok((revision, entries.len()))
    }
}

fn find(entries: Vec<Entry>, query: &str) -> Result<Entry, CliError> {
    if let Some(entry) = entries.iter().find(|e| e.id == query) {
        return Ok(entry.clone());
    }
    let wanted = query.to_lowercase();
    let mut matches: Vec<Entry> = entries
        .into_iter()
        .filter(|e| e.item.name.to_lowercase() == wanted)
        .collect();
    match matches.len() {
        0 => Err(CliError::ItemNotFound(query.to_owned())),
        1 => Ok(matches.remove(0)),
        _ => Err(CliError::Ambiguous(query.to_owned())),
    }
}
