//! What the handlers share: the services, the clock and the token signer.

use std::sync::Arc;

use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::{header, request::Parts};
use axum::Json;
use passguardian_server_domain::ports::{Clock, IdGenerator, StorageProbe, UnitOfWork};
use passguardian_server_domain::{HealthService, Service};
use serde::de::DeserializeOwned;

use crate::error::ApiError;
use crate::tokens::{Claims, TokenKind, TokenSigner};
use passguardian_server_domain::DomainError;

/// Everything a storage backend must be to serve the API.
pub trait Backend: UnitOfWork + StorageProbe + Clone + 'static {}
impl<T: UnitOfWork + StorageProbe + Clone + 'static> Backend for T {}

/// Shared state of the API.
#[derive(Debug)]
pub struct AppState<U: Backend, C: Clock + Clone + 'static, G: IdGenerator + 'static> {
    pub(crate) service: Service<U, C, G>,
    pub(crate) health: HealthService<U>,
    pub(crate) clock: C,
    pub(crate) signer: TokenSigner,
}

impl<U: Backend, C: Clock + Clone + 'static, G: IdGenerator + 'static> AppState<U, C, G> {
    /// Builds the state around a storage backend.
    #[must_use]
    pub fn new(store: U, clock: C, ids: G, signer: TokenSigner) -> Arc<Self> {
        Arc::new(Self {
            service: Service::new(store.clone(), clock.clone(), ids),
            health: HealthService::new(store),
            clock,
            signer,
        })
    }
}

/// A JSON body whose parse errors never echo the input.
pub(crate) struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(req, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|_| ApiError::from(DomainError::InvalidInput))
    }
}

/// The caller of a protected route, taken from its `Authorization: Bearer` access token.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Authenticated(pub Claims);

impl<U, C, G> FromRequestParts<Arc<AppState<U, C, G>>> for Authenticated
where
    U: Backend,
    C: Clock + Clone + 'static,
    G: IdGenerator + 'static,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState<U, C, G>>,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(DomainError::InvalidCredentials)?;
        let claims = state
            .signer
            .verify(token, TokenKind::Access, state.clock.now())?;
        Ok(Self(claims))
    }
}
