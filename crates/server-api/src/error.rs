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
            DomainError::InvalidId | DomainError::InvalidEmail | DomainError::InvalidName => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "the request contains an invalid value",
            ),
            DomainError::RevisionOverflow => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "internal error",
            ),
        };
        let body = ApiErrorBody {
            code: code.into(),
            message: message.into(),
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_of(error: DomainError) -> StatusCode {
        ApiError::from(error).into_response().status()
    }

    #[test]
    fn unavailable_maps_to_503() {
        assert_eq!(
            status_of(DomainError::Unavailable),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn invalid_input_maps_to_400() {
        for error in [
            DomainError::InvalidId,
            DomainError::InvalidEmail,
            DomainError::InvalidName,
        ] {
            assert_eq!(status_of(error), StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn revision_overflow_maps_to_500_without_details() {
        assert_eq!(
            status_of(DomainError::RevisionOverflow),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
