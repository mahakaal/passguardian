//! Handler for `GET /api/v1/health`.

use std::sync::Arc;

use axum::{extract::State, Json};
use passguardian_proto::HealthResponse;
use passguardian_server_domain::ports::{Clock, IdGenerator};

use crate::error::ApiError;
use crate::state::{AppState, Backend};

pub(crate) async fn get_health<U, C, G>(
    State(state): State<Arc<AppState<U, C, G>>>,
) -> Result<Json<HealthResponse>, ApiError>
where
    U: Backend,
    C: Clock + Clone + 'static,
    G: IdGenerator + 'static,
{
    state.health.check().await?;
    Ok(Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    }))
}
