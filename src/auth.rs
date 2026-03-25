//! Exploratory JWT layer: verify bearer token, hydrate a user from in-memory store, stash in request extensions.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::{AppState, User};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject — demo uses existing `User.username`.
    pub sub: String,
    pub exp: usize,
}

/// What downstream handlers read (set by auth middleware).
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub claims: JwtClaims,
    pub user: User,
}

/// Bearer JWT required: [`auth_middleware`] must run first; yields hydrated [`AuthContext`].
#[derive(Debug, Clone)]
pub struct CurrentUser(pub AuthContext);

impl axum::extract::FromRequestParts<AppState> for CurrentUser {
    type Rejection = StatusCode;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &AppState,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let ctx = parts.extensions.get::<AuthContext>().cloned();
        async move {
            let ctx = ctx.ok_or(StatusCode::UNAUTHORIZED)?;
            Ok(CurrentUser(ctx))
        }
    }
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let token = match bearer_token(request.headers().get(AUTHORIZATION)) {
        Some(t) => t,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let key = DecodingKey::from_secret(state.jwt_hmac_secret.as_ref());
    let claims = match decode_jwt(&key, &token) {
        Ok(c) => c,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let user = {
        let users = state.users.lock().unwrap();
        users
            .iter()
            .find(|u| u.username == claims.sub)
            .cloned()
    };

    let Some(user) = user else {
        return StatusCode::FORBIDDEN.into_response();
    };

    request.extensions_mut().insert(AuthContext { claims, user });
    next.run(request).await
}

fn bearer_token(header: Option<&axum::http::HeaderValue>) -> Option<String> {
    let h = header?.to_str().ok()?;
    let rest = h.strip_prefix("Bearer ")?;
    let token = rest.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

fn decode_jwt(key: &DecodingKey, token: &str) -> Result<JwtClaims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    let data = decode::<JwtClaims>(token, key, &validation)?;
    Ok(data.claims)
}

/// Mint an HS256 JWT for demos/tests (`sub` should match a `User.username` in the store).
pub fn encode_demo_jwt(
    key: &jsonwebtoken::EncodingKey,
    sub: &str,
    exp_unix: usize,
) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = JwtClaims { sub: sub.into(), exp: exp_unix };
    let header = jsonwebtoken::Header::default();
    jsonwebtoken::encode(&header, &claims, key)
}

/// Build Axum decoding key from shared secret bytes (HS256 demo).
pub fn decoding_key_from_secret(secret: &[u8]) -> DecodingKey {
    DecodingKey::from_secret(secret)
}

pub fn encoding_key_from_secret(secret: &[u8]) -> jsonwebtoken::EncodingKey {
    jsonwebtoken::EncodingKey::from_secret(secret)
}
