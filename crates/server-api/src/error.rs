//! Mapping `DomainError` → HTTP response. The single place where this translation happens.

use axum::{http::StatusCode, response::IntoResponse, response::Response, Json};
use passguardian_proto::ApiErrorBody;
use passguardian_server_domain::DomainError;

pub(crate) struct ApiError(DomainError);

impl From<DomainError> for ApiError {
    fn from(value: DomainError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self.0 {
            DomainError::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "service temporarily unavailable",
            ),
        };
        let body = ApiErrorBody {
            code: code.into(),
            message: message.into(),
        };
        (status, Json(body)).into_response()
    }
}
