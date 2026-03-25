//! Drift-style checks: runtime middleware + OpenAPI `security` for `POST /users`.

use axum::{body::Body, http::Request, http::StatusCode};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;
use utoipa::OpenApi;
use utoipa_demo::auth::{encode_demo_jwt, encoding_key_from_secret};
use utoipa_demo::{demo_state_with_secret, router, ApiDoc};

fn openapi_json_value() -> Value {
    let s = ApiDoc::openapi().to_pretty_json().expect("openapi json");
    serde_json::from_str(&s).expect("parse openapi")
}

fn exp_later() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
        + 3600
}

#[tokio::test]
async fn post_users_without_token_is_unauthorized() {
    let app = router(demo_state_with_secret(b"test-secret"));

    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"bob"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn post_users_with_valid_jwt_succeeds_and_openapi_lists_bearer_security() {
    let state = demo_state_with_secret(b"test-secret");
    let app = router(state.clone());

    let token = encode_demo_jwt(
        &encoding_key_from_secret(b"test-secret"),
        "alice",
        exp_later(),
    )
    .unwrap();

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(r#"{"username":"bob"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::CREATED);

    // Spec from `ApiDoc` (same document Swagger UI is configured to serve).
    let v = openapi_json_value();
    let security = &v["paths"]["/users"]["post"]["security"];
    assert!(security.is_array(), "expected security array, got {security}");
    assert!(
        security.to_string().contains("bearer_auth"),
        "OpenAPI should reference bearer_auth for POST /users: {security}"
    );
}
