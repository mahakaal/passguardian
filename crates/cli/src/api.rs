//! Blocking HTTP client for API v1.

use std::time::Duration;

use passguardian_proto::{
    ApiErrorBody, CipherResponse, CreateCipherRequest, LoginRequest, RefreshRequest,
    RegisterRequest, SessionResponse, SyncResponse, TokenResponse,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use ureq::http::Response;
use ureq::{Agent, Body};

use crate::error::CliError;

/// Talks to one server.
#[derive(Debug, Clone)]
pub struct ApiClient {
    base: String,
    agent: Agent,
}

fn network(error: &ureq::Error) -> CliError {
    CliError::Network(error.to_string())
}

/// Turns a response into the expected body or a [`CliError::Server`].
fn finish<T: DeserializeOwned>(mut response: Response<Body>) -> Result<T, CliError> {
    let status = response.status().as_u16();
    if (200..300).contains(&status) {
        return response
            .body_mut()
            .read_json::<T>()
            .map_err(|e| network(&e));
    }
    let message = response
        .body_mut()
        .read_json::<ApiErrorBody>()
        .map_or_else(|_| "no details".to_owned(), |body| body.message);
    Err(CliError::Server { status, message })
}

impl ApiClient {
    /// A client for the server at `base` (for example `https://pass.example.org`).
    #[must_use]
    pub fn new(base: &str) -> Self {
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        Self {
            base: base.trim_end_matches('/').to_owned(),
            agent,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1/{path}", self.base)
    }

    fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
        body: &B,
    ) -> Result<T, CliError> {
        let mut request = self.agent.post(self.url(path));
        if let Some(token) = token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        finish(request.send_json(body).map_err(|e| network(&e))?)
    }

    fn get<T: DeserializeOwned>(&self, path: &str, token: &str) -> Result<T, CliError> {
        let response = self
            .agent
            .get(self.url(path))
            .header("Authorization", format!("Bearer {token}"))
            .call()
            .map_err(|e| network(&e))?;
        finish(response)
    }

    /// `POST /accounts`.
    pub fn register(&self, request: &RegisterRequest) -> Result<SessionResponse, CliError> {
        self.post("accounts", None, request)
    }

    /// `POST /login`.
    pub fn login(&self, request: &LoginRequest) -> Result<SessionResponse, CliError> {
        self.post("login", None, request)
    }

    /// `POST /token`.
    pub fn refresh(&self, refresh_token: &str) -> Result<TokenResponse, CliError> {
        self.post(
            "token",
            None,
            &RefreshRequest {
                refresh_token: refresh_token.to_owned(),
            },
        )
    }

    /// `POST /ciphers`.
    pub fn create_cipher(
        &self,
        token: &str,
        request: &CreateCipherRequest,
    ) -> Result<CipherResponse, CliError> {
        self.post("ciphers", Some(token), request)
    }

    /// `DELETE /ciphers/{id}?revision=N`.
    pub fn delete_cipher(
        &self,
        token: &str,
        id: &str,
        revision: u64,
    ) -> Result<CipherResponse, CliError> {
        let response = self
            .agent
            .delete(self.url(&format!("ciphers/{id}?revision={revision}")))
            .header("Authorization", format!("Bearer {token}"))
            .call()
            .map_err(|e| network(&e))?;
        finish(response)
    }

    /// `GET /sync?since=N`.
    pub fn sync(&self, token: &str, since: u64) -> Result<SyncResponse, CliError> {
        self.get(&format!("sync?since={since}"), token)
    }
}

/// Whether an error is "the access token is no good", worth one refresh.
#[must_use]
pub fn is_unauthorized(error: &CliError) -> bool {
    matches!(error, CliError::Server { status: 401, .. })
}
