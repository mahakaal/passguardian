//! PassGuardian server HTTP layer.
//!
//! Handlers contain no logic: they validate input, call a domain service
//! and map the result (or the error) to an HTTP response.

mod error;
mod health;

use std::sync::Arc;

use axum::{routing::get, Router};
use passguardian_server_domain::{ports::StorageProbe, HealthService};

/// Builds the API v1 router, generic over storage.
pub fn router<S>(health: HealthService<S>) -> Router
where
    S: StorageProbe + 'static,
{
    Router::new()
        .route("/api/v1/health", get(health::get_health::<S>))
        .with_state(Arc::new(health))
}

#[cfg(test)]
mod tests {
    use std::future::{ready, Future};

    use axum::{body::Body, http::Request, http::StatusCode};
    use http_body_util::BodyExt;
    use passguardian_proto::HealthResponse;
    use passguardian_server_data::NoopStorage;
    use passguardian_server_domain::DomainError;
    use tower::ServiceExt;

    use super::*;

    struct Down;

    impl StorageProbe for Down {
        fn ping(&self) -> impl Future<Output = Result<(), DomainError>> + Send {
            ready(Err(DomainError::Unavailable))
        }
    }

    #[tokio::test]
    async fn health_returns_ok_json() {
        let app = router(HealthService::new(NoopStorage));
        let res = app
            .oneshot(Request::get("/api/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let body: HealthResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body.status, "ok");
    }

    #[tokio::test]
    async fn health_returns_503_when_storage_is_down() {
        let app = router(HealthService::new(Down));
        let res = app
            .oneshot(Request::get("/api/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
