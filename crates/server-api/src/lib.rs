//! PassGuardian server HTTP layer.
//!
//! Handlers contain no logic: they validate input, call a domain service
//! and map the result (or the error) to an HTTP response. See ADR 0009 for the endpoints.

mod error;
mod health;
mod routes;
mod state;
pub mod tokens;

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post, put};
use axum::Router;
use passguardian_server_domain::ports::{Clock, IdGenerator};
use passguardian_server_domain::DomainError;

use crate::error::ApiError;
pub use state::{AppState, Backend};

/// Largest request body accepted: an encrypted item is small, a megabyte is generous.
const MAX_BODY_BYTES: usize = 1024 * 1024;

async fn not_found() -> ApiError {
    ApiError::from(DomainError::NotFound)
}

/// Builds the API v1 router.
pub fn router<U, C, G>(state: Arc<AppState<U, C, G>>) -> Router
where
    U: Backend,
    C: Clock + Clone + 'static,
    G: IdGenerator + 'static,
{
    Router::new()
        .route("/api/v1/health", get(health::get_health::<U, C, G>))
        .route("/api/v1/accounts", post(routes::register::<U, C, G>))
        .route("/api/v1/login", post(routes::login::<U, C, G>))
        .route("/api/v1/token", post(routes::refresh_token::<U, C, G>))
        .route(
            "/api/v1/devices/{id}",
            delete(routes::revoke_device::<U, C, G>),
        )
        .route("/api/v1/ciphers", post(routes::create_cipher::<U, C, G>))
        .route(
            "/api/v1/ciphers/{id}",
            put(routes::update_cipher::<U, C, G>).delete(routes::delete_cipher::<U, C, G>),
        )
        .route("/api/v1/sync", get(routes::sync::<U, C, G>))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}
