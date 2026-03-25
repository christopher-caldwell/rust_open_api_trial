//! Default binary: serves the app defined in [`utoipa_demo`].


//! Axum + utoipa demo with JWT middleware and plain `#[utoipa::path(..., security(...))]` on protected handlers.

pub mod auth;

use auth::CurrentUser;
use axum::{
    extract::{Path, State},
    middleware,
    routing::{get, post},
    Json, Router,
};
use jsonwebtoken::DecodingKey;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi, ToSchema,
};
use utoipa_swagger_ui::SwaggerUi;
use utoipauto::utoipauto;

// --- DATA MODELS ---

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct User {
    #[schema(example = 1)]
    pub id: u64,
    #[schema(example = "rust_ace")]
    pub username: String,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateUserRequest {
    /// The name for the new user
    #[schema(example = "new_developer")]
    pub username: String,
}

// --- SHARED STATE ---

#[derive(Clone)]
pub struct AppState {
    pub users: Arc<Mutex<Vec<User>>>,
    pub jwt_hmac_secret: Arc<[u8]>,
}

impl AppState {
    pub fn jwt_decoding_key(&self) -> DecodingKey {
        DecodingKey::from_secret(self.jwt_hmac_secret.as_ref())
    }
}

// --- HANDLERS ---

#[utoipa::path(
    get,
    path = "/users",
    tag = "Users",
    responses(
        (status = 200, description = "Users", body = User),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Token valid but subject not allowed for this API")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_users(
    CurrentUser(_auth): CurrentUser,
) -> (axum::http::StatusCode, Json<User>) {
    println!("Getting users w/ auth: {}", _auth.user.id);
    let user: User = User{
        id: 1,
        username: String::from("Jim")
    };
     return (axum::http::StatusCode::OK, Json(user));
}

#[utoipa::path(
    post,
    path = "/users",
    tag = "Users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created", body = User),
        (status = 400, description = "Bad Request"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Token valid but subject not allowed for this API")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_user(
    State(state): State<AppState>,
    CurrentUser(_auth): CurrentUser,
    Json(payload): Json<CreateUserRequest>,
) -> (axum::http::StatusCode, Json<User>) {
    let mut users = state.users.lock().unwrap();
    let new_user = User {
        id: (users.len() + 1) as u64,
        username: payload.username,
    };
    users.push(new_user.clone());
    (axum::http::StatusCode::CREATED, Json(new_user))
}

#[utoipa::path(
    get,
    path = "/users/{id}",
    tag = "Users",
    params(
        ("id" = u64, Path, description = "Numeric ID of the user")
    ),
    responses(
        (status = 200, description = "User found", body = User),
        (status = 404, description = "User not found")
    )
)]
pub async fn get_user(
    Path(id): Path<u64>,
    State(state): State<AppState>,
) -> Result<Json<User>, axum::http::StatusCode> {
    let users = state.users.lock().unwrap();
    users
        .iter()
        .find(|u| u.id == id)
        .cloned()
        .map(Json)
        .ok_or(axum::http::StatusCode::NOT_FOUND)
}

// --- OPENAPI ---

// Only `lib.rs` so we do not pull in e.g. `base_main.rs` or other examples under `src/`.
#[utoipauto(paths = "src")]
#[derive(OpenApi)]
#[openapi(
    modifiers(&SecurityAddon),
    info(
        title = "My Awesome Production API",
        version = "1.0.0",
        description = "This is a custom description for my Axum-powered service.",
        license(name = "MIT"),
        contact(name = "Support Team", email = "support@example.com")
    )
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}

pub fn router(state: AppState) -> Router {
    let swagger_ui =
        SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi());

    let public = Router::new().route("/users/{id}", get(get_user));

    let protected = Router::new()
        .route("/users", post(create_user))
        .route("/users", get(get_users))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ));

    Router::new()
        .merge(public)
        .merge(protected)
        .merge(swagger_ui)
        .with_state(state)
}

/// Deterministic demo state (good for tests; avoids env races under parallel `cargo test`).
pub fn demo_state_with_secret(secret: impl AsRef<[u8]>) -> AppState {
    AppState {
        users: Arc::new(Mutex::new(vec![User {
            id: 1,
            username: "alice".into(),
        }])),
        jwt_hmac_secret: secret.as_ref().to_vec().into_boxed_slice().into(),
    }
}

pub fn demo_state() -> AppState {
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev-secret-change-me".into());
    demo_state_with_secret(secret.into_bytes())
}

pub async fn run() {
    let state = demo_state();
    let app = router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("API Docs: http://localhost:3000/swagger-ui");
    axum::serve(listener, app).await.unwrap();
}


#[tokio::main]
async fn main() {
    run().await;
}
