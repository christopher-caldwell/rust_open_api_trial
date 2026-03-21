use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi, ToSchema,
};
use utoipa_swagger_ui::SwaggerUi;
use utoipauto::utoipauto;

// --- 1. DATA MODELS ---

// Serialize because it's sent to the client
#[derive(Serialize, Clone, ToSchema)]
pub struct User {
    #[schema(example = 1)]
    pub id: u64,
    #[schema(example = "rust_ace")]
    pub username: String,
}

// Deserialize because it's received from the client
#[derive(Deserialize, ToSchema)]
pub struct CreateUserRequest {
    /// The name for the new user
    #[schema(example = "new_developer")]
    pub username: String,
}

// --- 2. SHARED STATE ---
type AppState = Arc<Mutex<Vec<User>>>;

// --- 3. HANDLERS ---

/// Create a new user
///
/// This endpoint takes a JSON body and adds a user to our "database".
#[utoipa::path(
    post,
    path = "/users",
    tag = "Users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created", body = User),
        (status = 400, description = "Bad Request")
    ),
    security(("bearer_auth" = []))
)]
async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> (axum::http::StatusCode, Json<User>) {
    let mut users = state.lock().unwrap();
    let new_user = User {
        id: (users.len() + 1) as u64,
        username: payload.username,
    };
    users.push(new_user.clone());
    (axum::http::StatusCode::CREATED, Json(new_user))
}

/// Get user by ID
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
async fn get_user(
    Path(id): Path<u64>,
    State(state): State<AppState>,
) -> Result<Json<User>, axum::http::StatusCode> {
    let users = state.lock().unwrap();
    users
        .iter()
        .find(|u| u.id == id)
        .cloned()
        .map(Json)
        .ok_or(axum::http::StatusCode::NOT_FOUND)
}

// --- 4. OPENAPI AGGREGATION ---

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
struct ApiDoc;

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

// --- 5. MAIN ---

#[tokio::main]
async fn main() {
    let shared_state = Arc::new(Mutex::new(vec![User {
        id: 1,
        username: "alice".into(),
    }]));

    let app = Router::new()
        // Link the routes
        .route("/users", post(create_user))
        .route("/users/{id}", get(get_user))
        // Add Swagger UI
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("🚀 API Docs: http://localhost:3000/swagger-ui");
    axum::serve(listener, app).await.unwrap();
}
