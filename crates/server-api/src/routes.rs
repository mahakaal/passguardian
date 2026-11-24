//! Handlers. They validate input, call a domain service and map the result; no logic here.

use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use passguardian_proto::{
    CipherResponse, CreateCipherRequest, LoginRequest, RefreshRequest, RegisterRequest,
    SessionResponse, SyncResponse, TokenResponse, UpdateCipherRequest,
};
use passguardian_server_domain::ports::{Clock, IdGenerator};
use passguardian_server_domain::{
    Cipher, CipherId, DeviceId, DomainError, FolderId, Registration, Revision, Session,
};
use serde::Deserialize;

use crate::error::ApiError;
use crate::state::{ApiJson, AppState, Authenticated, Backend};
use crate::tokens::{Claims, TokenKind};

type Shared<U, C, G> = State<Arc<AppState<U, C, G>>>;

fn cipher_response(cipher: &Cipher) -> CipherResponse {
    CipherResponse {
        id: cipher.id().to_string(),
        folder_id: cipher.folder_id().map(|f| f.to_string()),
        data: cipher.data().to_vec(),
        revision: cipher.revision().get(),
        deleted: cipher.is_deleted(),
    }
}

fn parse_folder(folder_id: Option<&str>) -> Result<Option<FolderId>, DomainError> {
    folder_id.map(str::parse).transpose()
}

fn session_response<U, C, G>(
    state: &AppState<U, C, G>,
    session: Session,
) -> Result<SessionResponse, ApiError>
where
    U: Backend,
    C: Clock + Clone + 'static,
    G: IdGenerator + 'static,
{
    let claims = Claims {
        user_id: session.user_id,
        device_id: session.device_id,
    };
    let now = state.clock.now();
    Ok(SessionResponse {
        user_id: session.user_id.to_string(),
        device_id: session.device_id.to_string(),
        key_envelope: session.key_envelope,
        access_token: state.signer.issue(TokenKind::Access, claims, now)?,
        refresh_token: state.signer.issue(TokenKind::Refresh, claims, now)?,
    })
}

pub(crate) async fn register<U, C, G>(
    State(state): Shared<U, C, G>,
    ApiJson(request): ApiJson<RegisterRequest>,
) -> Result<(StatusCode, Json<SessionResponse>), ApiError>
where
    U: Backend,
    C: Clock + Clone + 'static,
    G: IdGenerator + 'static,
{
    let session = state
        .service
        .register(&Registration {
            email: &request.email,
            auth_key: &request.auth_key,
            key_envelope: &request.key_envelope,
            device_name: &request.device_name,
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(session_response(&state, session)?),
    ))
}

pub(crate) async fn login<U, C, G>(
    State(state): Shared<U, C, G>,
    ApiJson(request): ApiJson<LoginRequest>,
) -> Result<Json<SessionResponse>, ApiError>
where
    U: Backend,
    C: Clock + Clone + 'static,
    G: IdGenerator + 'static,
{
    let session = state
        .service
        .login(&request.email, &request.auth_key, &request.device_name)
        .await?;
    Ok(Json(session_response(&state, session)?))
}

pub(crate) async fn refresh_token<U, C, G>(
    State(state): Shared<U, C, G>,
    ApiJson(request): ApiJson<RefreshRequest>,
) -> Result<Json<TokenResponse>, ApiError>
where
    U: Backend,
    C: Clock + Clone + 'static,
    G: IdGenerator + 'static,
{
    let now = state.clock.now();
    let claims = state
        .signer
        .verify(&request.refresh_token, TokenKind::Refresh, now)?;
    state
        .service
        .refresh(claims.user_id, claims.device_id)
        .await?;
    Ok(Json(TokenResponse {
        access_token: state.signer.issue(TokenKind::Access, claims, now)?,
    }))
}

pub(crate) async fn revoke_device<U, C, G>(
    State(state): Shared<U, C, G>,
    Authenticated(caller): Authenticated,
    Path(device_id): Path<String>,
) -> Result<StatusCode, ApiError>
where
    U: Backend,
    C: Clock + Clone + 'static,
    G: IdGenerator + 'static,
{
    let device_id: DeviceId = device_id.parse()?;
    state
        .service
        .revoke_device(caller.user_id, device_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn create_cipher<U, C, G>(
    State(state): Shared<U, C, G>,
    Authenticated(caller): Authenticated,
    ApiJson(request): ApiJson<CreateCipherRequest>,
) -> Result<(StatusCode, Json<CipherResponse>), ApiError>
where
    U: Backend,
    C: Clock + Clone + 'static,
    G: IdGenerator + 'static,
{
    let cipher = state
        .service
        .create_cipher(
            caller.user_id,
            request.id.parse()?,
            parse_folder(request.folder_id.as_deref())?,
            request.data,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(cipher_response(&cipher))))
}

pub(crate) async fn update_cipher<U, C, G>(
    State(state): Shared<U, C, G>,
    Authenticated(caller): Authenticated,
    Path(cipher_id): Path<String>,
    ApiJson(request): ApiJson<UpdateCipherRequest>,
) -> Result<Json<CipherResponse>, ApiError>
where
    U: Backend,
    C: Clock + Clone + 'static,
    G: IdGenerator + 'static,
{
    let cipher_id: CipherId = cipher_id.parse()?;
    let cipher = state
        .service
        .update_cipher(
            caller.user_id,
            cipher_id,
            Revision::new(request.revision),
            parse_folder(request.folder_id.as_deref())?,
            request.data,
        )
        .await?;
    Ok(Json(cipher_response(&cipher)))
}

#[derive(Debug, Deserialize)]
pub(crate) struct RevisionQuery {
    revision: u64,
}

pub(crate) async fn delete_cipher<U, C, G>(
    State(state): Shared<U, C, G>,
    Authenticated(caller): Authenticated,
    Path(cipher_id): Path<String>,
    query: Result<Query<RevisionQuery>, QueryRejection>,
) -> Result<Json<CipherResponse>, ApiError>
where
    U: Backend,
    C: Clock + Clone + 'static,
    G: IdGenerator + 'static,
{
    let Query(query) = query.map_err(|_| DomainError::InvalidInput)?;
    let cipher_id: CipherId = cipher_id.parse()?;
    let cipher = state
        .service
        .delete_cipher(caller.user_id, cipher_id, Revision::new(query.revision))
        .await?;
    Ok(Json(cipher_response(&cipher)))
}

#[derive(Debug, Deserialize)]
pub(crate) struct SyncQuery {
    since: Option<u64>,
}

pub(crate) async fn sync<U, C, G>(
    State(state): Shared<U, C, G>,
    Authenticated(caller): Authenticated,
    query: Result<Query<SyncQuery>, QueryRejection>,
) -> Result<Json<SyncResponse>, ApiError>
where
    U: Backend,
    C: Clock + Clone + 'static,
    G: IdGenerator + 'static,
{
    let Query(query) = query.map_err(|_| DomainError::InvalidInput)?;
    let response = state
        .service
        .sync(caller.user_id, Revision::new(query.since.unwrap_or(0)))
        .await?;
    Ok(Json(SyncResponse {
        revision: response.revision.get(),
        changes: response.changes.iter().map(cipher_response).collect(),
    }))
}
