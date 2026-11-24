//! Mapping `DomainError` → HTTP response. The single place where this translation happens.
//!
//! Bodies are fixed texts: they never echo the request, a storage message or a stack trace.

use axum::{http::StatusCode, response::IntoResponse, response::Response, Json};
use passguardian_proto::ApiErrorBody;
use passguardian_server_domain::DomainError;

#[derive(Debug)]
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
            DomainError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "invalid credentials",
            ),
            DomainError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many attempts, try again later",
            ),
            DomainError::NotFound => (StatusCode::NOT_FOUND, "not_found", "not found"),
            DomainError::Conflict => (
                StatusCode::CONFLICT,
                "conflict",
                "the request conflicts with the current state",
            ),
            DomainError::InvalidId
            | DomainError::InvalidEmail
            | DomainError::InvalidName
            | DomainError::InvalidInput => (
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
            DomainError::InvalidInput,
        ] {
            assert_eq!(status_of(error), StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn authentication_and_lookup_errors_map_to_401_429_404() {
        assert_eq!(
            status_of(DomainError::InvalidCredentials),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status_of(DomainError::RateLimited),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(status_of(DomainError::NotFound), StatusCode::NOT_FOUND);
    }

    #[test]
    fn conflict_maps_to_409() {
        assert_eq!(status_of(DomainError::Conflict), StatusCode::CONFLICT);
    }

    #[test]
    fn revision_overflow_maps_to_500_without_details() {
        assert_eq!(
            status_of(DomainError::RevisionOverflow),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
