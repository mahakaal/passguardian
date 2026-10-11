//! Handler for `GET /api/v1/health`.

use std::sync::Arc;

use axum::{extract::State, Json};
use passguardian_proto::HealthResponse;
use passguardian_server_domain::{ports::StorageProbe, HealthService};

use crate::error::ApiError;

pub(crate) async fn get_health<S: StorageProbe>(
    State(service): State<Arc<HealthService<S>>>,
) -> Result<Json<HealthResponse>, ApiError> {
    service.check().await?;
    Ok(Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    }))
}
