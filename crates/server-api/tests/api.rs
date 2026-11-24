//! HTTP tests: the real router on top of the domain with in-memory storage, no sockets.

// Test helpers outside `#[test]` functions: failing fast with unwrap is what we want here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::future::Future;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use passguardian_server_api::tokens::TokenSigner;
use passguardian_server_api::{router, AppState};
use passguardian_server_domain::ports::{StorageProbe, UnitOfWork};
use passguardian_server_domain::testing::{InMemoryStore, ManualClock, SequentialIds};
use passguardian_server_domain::{DomainError, Timestamp};
use serde_json::{json, Value};
use tower::ServiceExt;

const KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="; // 32 bytes of 7
const OTHER_KEY: &str = "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="; // 32 bytes of 8
const CIPHER_A: &str = "00000000-0000-0000-0000-00000000000a";
const CIPHER_B: &str = "00000000-0000-0000-0000-00000000000b";

fn app_with_clock() -> (Router, ManualClock) {
    let clock = ManualClock::new(Timestamp::from_unix_seconds(1_000_000));
    let state = AppState::new(
        InMemoryStore::new(),
        clock.clone(),
        SequentialIds::new(),
        TokenSigner::new(&[9; 32]).unwrap(),
    );
    (router(state), clock)
}

fn app() -> Router {
    app_with_clock().0
}

async fn call(
    app: &Router,
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = match body {
        Some(value) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn register(app: &Router, email: &str, key: &str) -> Value {
    let (status, body) = call(
        app,
        Method::POST,
        "/api/v1/accounts",
        None,
        Some(json!({"email": email, "auth_key": key, "key_envelope": "ZW52", "device_name": "laptop"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body
}

fn access(session: &Value) -> String {
    session["access_token"].as_str().unwrap().to_owned()
}

async fn create(app: &Router, token: &str, id: &str, data: &str) -> Value {
    let (status, body) = call(
        app,
        Method::POST,
        "/api/v1/ciphers",
        Some(token),
        Some(json!({"id": id, "folder_id": null, "data": data})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body
}

/// A fresh access token for the device that registered.
async fn renewed_access(app: &Router, session: &Value) -> String {
    let (status, body) = call(
        app,
        Method::POST,
        "/api/v1/token",
        None,
        Some(json!({"refresh_token": session["refresh_token"]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    body["access_token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn health_returns_200_ok_json() {
    let (status, body) = call(&app(), Method::GET, "/api/v1/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn health_returns_503_when_storage_is_down() {
    #[derive(Clone)]
    struct Down(InMemoryStore);
    impl StorageProbe for Down {
        fn ping(&self) -> impl Future<Output = Result<(), DomainError>> + Send {
            std::future::ready(Err(DomainError::Unavailable))
        }
    }
    impl UnitOfWork for Down {
        type Tx = <InMemoryStore as UnitOfWork>::Tx;
        fn begin(&self) -> impl Future<Output = Result<Self::Tx, DomainError>> + Send {
            self.0.begin()
        }
    }
    let state = AppState::new(
        Down(InMemoryStore::new()),
        ManualClock::new(Timestamp::from_unix_seconds(0)),
        SequentialIds::new(),
        TokenSigner::new(&[9; 32]).unwrap(),
    );
    let (status, body) = call(&router(state), Method::GET, "/api/v1/health", None, None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["code"], "unavailable");
}

#[tokio::test]
async fn unknown_route_returns_404_error_body() {
    let (status, body) = call(&app(), Method::GET, "/api/v1/nope", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "not_found");
}

#[tokio::test]
async fn malformed_json_returns_400_without_echoing_input() {
    let request = Request::post("/api/v1/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"email": "secret-marker-123", "auth_key": "#))
        .unwrap();
    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("secret-marker-123"), "{text}");
    assert!(
        !text.to_lowercase().contains("serde") && !text.contains("line "),
        "{text}"
    );
}

#[tokio::test]
async fn protected_routes_without_a_valid_token_return_401() {
    let app = app();
    for (method, uri) in [
        (Method::GET, "/api/v1/sync"),
        (Method::POST, "/api/v1/ciphers"),
        (
            Method::PUT,
            "/api/v1/ciphers/00000000-0000-0000-0000-00000000000a",
        ),
        (
            Method::DELETE,
            "/api/v1/devices/00000000-0000-0000-0000-00000000000a",
        ),
    ] {
        let (status, _) = call(&app, method.clone(), uri, None, Some(json!({}))).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {uri} without token"
        );
        let (status, _) = call(&app, method.clone(), uri, Some("garbage"), Some(json!({}))).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {uri} with a bad token"
        );
    }
}

#[tokio::test]
async fn a_refresh_token_cannot_be_used_as_an_access_token() {
    let app = app();
    let session = register(&app, "alice@example.com", KEY).await;
    let refresh = session["refresh_token"].as_str().unwrap();
    let (status, _) = call(&app, Method::GET, "/api/v1/sync", Some(refresh), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn full_flow_register_login_create_update_sync_delete() {
    let app = app();
    let session = register(&app, "alice@example.com", KEY).await;
    assert_eq!(session["key_envelope"], "ZW52");

    // A second device logs in and sees the same user.
    let (status, login) = call(
        &app,
        Method::POST,
        "/api/v1/login",
        None,
        Some(json!({"email": "ALICE@example.com", "auth_key": KEY, "device_name": "phone"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(login["user_id"], session["user_id"]);
    assert_ne!(login["device_id"], session["device_id"]);

    let token = access(&login);
    let created = create(&app, &token, CIPHER_A, "AQID").await;
    assert_eq!(created["revision"], 1);

    let (status, updated) = call(
        &app,
        Method::PUT,
        &format!("/api/v1/ciphers/{CIPHER_A}"),
        Some(&token),
        Some(json!({"revision": 1, "folder_id": null, "data": "BAUG"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["revision"], 2);
    assert_eq!(updated["data"], "BAUG");

    // The stale writer loses.
    let (status, body) = call(
        &app,
        Method::PUT,
        &format!("/api/v1/ciphers/{CIPHER_A}"),
        Some(&token),
        Some(json!({"revision": 1, "folder_id": null, "data": "AAAA"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "conflict");

    let (status, deleted) = call(
        &app,
        Method::DELETE,
        &format!("/api/v1/ciphers/{CIPHER_A}?revision=2"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(deleted["deleted"], true);
    assert_eq!(deleted["data"], "");

    let (status, sync) = call(
        &app,
        Method::GET,
        "/api/v1/sync?since=0",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sync["revision"], 3);
    assert_eq!(sync["changes"].as_array().unwrap().len(), 1);
    assert_eq!(sync["changes"][0]["deleted"], true);

    let (_, nothing) = call(
        &app,
        Method::GET,
        "/api/v1/sync?since=3",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(nothing["changes"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn duplicate_registration_is_a_409_that_names_no_field() {
    let app = app();
    register(&app, "alice@example.com", KEY).await;
    let (status, body) = call(
        &app,
        Method::POST,
        "/api/v1/accounts",
        None,
        Some(json!({"email": "alice@example.com", "auth_key": OTHER_KEY, "key_envelope": "ZW52", "device_name": "x"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(!body.to_string().to_lowercase().contains("email"), "{body}");
}

#[tokio::test]
async fn wrong_password_and_unknown_user_look_the_same() {
    let app = app();
    register(&app, "alice@example.com", KEY).await;
    let attempt = |email: &str, key: &str| {
        call(
            &app,
            Method::POST,
            "/api/v1/login",
            None,
            Some(json!({"email": email, "auth_key": key, "device_name": "x"})),
        )
    };
    let wrong = attempt("alice@example.com", OTHER_KEY).await;
    let unknown = attempt("nobody@example.com", KEY).await;
    assert_eq!(wrong.0, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong, unknown);
}

#[tokio::test]
async fn login_is_rate_limited_with_429() {
    let app = app();
    register(&app, "alice@example.com", KEY).await;
    let wrong = json!({"email": "alice@example.com", "auth_key": OTHER_KEY, "device_name": "x"});
    for _ in 0..5 {
        let (status, _) = call(
            &app,
            Method::POST,
            "/api/v1/login",
            None,
            Some(wrong.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let right = json!({"email": "alice@example.com", "auth_key": KEY, "device_name": "x"});
    let (status, body) = call(&app, Method::POST, "/api/v1/login", None, Some(right)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate_limited");
}

#[tokio::test]
async fn users_cannot_see_or_change_each_others_ciphers() {
    let app = app();
    let alice = access(&register(&app, "alice@example.com", KEY).await);
    let bob = access(&register(&app, "bob@example.com", OTHER_KEY).await);
    create(&app, &alice, CIPHER_A, "AQID").await;

    let (_, sync) = call(&app, Method::GET, "/api/v1/sync", Some(&bob), None).await;
    assert_eq!(sync["changes"].as_array().unwrap().len(), 0);
    let (status, _) = call(
        &app,
        Method::PUT,
        &format!("/api/v1/ciphers/{CIPHER_A}"),
        Some(&bob),
        Some(json!({"revision": 1, "folder_id": null, "data": "AAAA"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &app,
        Method::DELETE,
        &format!("/api/v1/ciphers/{CIPHER_A}?revision=1"),
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn refresh_gives_a_new_access_token_until_the_device_is_revoked() {
    let (app, clock) = app_with_clock();
    let first = register(&app, "alice@example.com", KEY).await;
    let (_, second) = call(
        &app,
        Method::POST,
        "/api/v1/login",
        None,
        Some(json!({"email": "alice@example.com", "auth_key": KEY, "device_name": "phone"})),
    )
    .await;

    // The access token expires; the refresh token still works.
    clock.advance(16 * 60);
    let old = access(&second);
    let (status, _) = call(&app, Method::GET, "/api/v1/sync", Some(&old), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let refresh = json!({"refresh_token": second["refresh_token"]});
    let (status, renewed) = call(
        &app,
        Method::POST,
        "/api/v1/token",
        None,
        Some(refresh.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &app,
        Method::GET,
        "/api/v1/sync",
        Some(renewed["access_token"].as_str().unwrap()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The first device revokes the second; the second can no longer refresh.
    let device = second["device_id"].as_str().unwrap();
    let first_access = renewed_access(&app, &first).await;
    let (status, _) = call(
        &app,
        Method::DELETE,
        &format!("/api/v1/devices/{device}"),
        Some(&first_access),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(&app, Method::POST, "/api/v1/token", None, Some(refresh)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bad_input_is_a_400_and_error_bodies_never_contain_internal_details() {
    let app = app();
    let token = access(&register(&app, "alice@example.com", KEY).await);
    let cases = vec![
        call(&app, Method::POST, "/api/v1/accounts", None, Some(json!({"email": "nope", "auth_key": KEY, "key_envelope": "ZW52", "device_name": "x"}))).await,
        call(&app, Method::POST, "/api/v1/accounts", None, Some(json!({"email": "a@b.it", "auth_key": "AAAA", "key_envelope": "ZW52", "device_name": "x"}))).await,
        call(&app, Method::POST, "/api/v1/accounts", None, Some(json!({"email": "a@b.it"}))).await,
        call(&app, Method::POST, "/api/v1/ciphers", Some(&token), Some(json!({"id": "not-a-uuid", "folder_id": null, "data": "AQID"}))).await,
        call(&app, Method::POST, "/api/v1/ciphers", Some(&token), Some(json!({"id": CIPHER_A, "folder_id": null, "data": "!!!"}))).await,
        call(&app, Method::DELETE, "/api/v1/ciphers/not-a-uuid?revision=1", Some(&token), None).await,
        call(&app, Method::DELETE, &format!("/api/v1/ciphers/{CIPHER_B}"), Some(&token), None).await,
        call(&app, Method::GET, "/api/v1/sync?since=abc", Some(&token), None).await,
    ];
    for (status, body) in cases {
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let text = body.to_string().to_lowercase();
        for forbidden in [
            "panic", "stack", "sqlx", "postgres", "serde", "line ", "column", "at src",
        ] {
            assert!(!text.contains(forbidden), "{forbidden} in {text}");
        }
        assert_eq!(
            body.as_object().unwrap().len(),
            2,
            "only code and message: {text}"
        );
    }
}
