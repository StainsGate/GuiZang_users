use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use gz_core::AppState;
use gz_web::ApiResponse;
use serde::{Deserialize, Serialize};

use crate::{api::extractors::AuthUser, error, infra, repo, service};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
}

#[derive(Debug, Deserialize)]
struct RegisterBody {
    email: Option<String>,
    phone: Option<String>,
    password: String,
    display_name: String,
}

#[derive(Debug, Deserialize)]
struct LoginBody {
    identifier: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct RefreshBody {
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
struct LogoutBody {
    refresh_token: String,
}

#[derive(Debug, Serialize)]
struct MeView {
    user: service::auth::UserView,
    roles: Vec<String>,
    permissions: Vec<String>,
}

async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    let jwt_cfg = infra::must_jwt_config(&state).await?;

    let idempotency_key = headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    let request_hash = sha256_hex_bytes(&body);

    if let Some(key) = &idempotency_key {
        if let Some(r) = repo::idempotency::get_valid(&pool, "auth.register", key)
            .await
            .map_err(|e| {
                error::with_context(
                    error::internal("db error"),
                    serde_json::json!({ "op": "get_idempotency", "err": e.to_string() }),
                )
            })?
        {
            if r.request_hash != request_hash {
                return Err(error::conflict("idempotency key conflict"));
            }

            let status = StatusCode::from_u16(r.status_code as u16).unwrap_or(StatusCode::OK);
            return Ok((status, Json(r.response_body)).into_response());
        }
    }

    let req: RegisterBody =
        serde_json::from_slice(&body).map_err(|_| error::bad_request("invalid json"))?;

    let result = service::auth::register(
        &pool,
        jwt_cfg.as_ref(),
        service::auth::RegisterInput {
            email: req.email,
            phone: req.phone,
            password: req.password,
            display_name: req.display_name,
        },
        None,
        user_agent(&headers),
    )
    .await?;

    let payload = ApiResponse::ok(result);
    if let Some(key) = idempotency_key {
        let expires_at = Utc::now() + Duration::hours(24);
        let response_body =
            serde_json::to_value(&payload).map_err(|_| error::internal("serialize error"))?;
        repo::idempotency::insert(
            &pool,
            "auth.register",
            &key,
            &request_hash,
            200,
            &response_body,
            expires_at,
        )
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "insert_idempotency", "err": e.to_string() }),
            )
        })?;
    }

    Ok(payload.into_response())
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LoginBody>,
) -> Result<ApiResponse<service::auth::TokenPair>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    let jwt_cfg = infra::must_jwt_config(&state).await?;

    let tokens = service::auth::login(
        &pool,
        jwt_cfg.as_ref(),
        service::auth::LoginInput {
            identifier: req.identifier,
            password: req.password,
        },
        None,
        user_agent(&headers),
    )
    .await?;

    Ok(ApiResponse::ok(tokens))
}

async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RefreshBody>,
) -> Result<ApiResponse<service::auth::TokenPair>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    let jwt_cfg = infra::must_jwt_config(&state).await?;

    let tokens = service::auth::refresh(
        &pool,
        jwt_cfg.as_ref(),
        service::auth::RefreshInput {
            refresh_token: req.refresh_token,
        },
        None,
        user_agent(&headers),
    )
    .await?;

    Ok(ApiResponse::ok(tokens))
}

async fn logout(
    State(state): State<AppState>,
    Json(req): Json<LogoutBody>,
) -> Result<ApiResponse<()>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    service::auth::logout(
        &pool,
        service::auth::LogoutInput {
            refresh_token: req.refresh_token,
        },
    )
    .await?;
    Ok(ApiResponse::<()>::empty_ok())
}

async fn me(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<ApiResponse<MeView>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;

    let user_row = repo::users::get_by_id(&pool, user.user_id)
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "get_user_by_id", "err": e.to_string() }),
            )
        })?
        .ok_or_else(|| error::not_found("user not found"))?;

    let roles = repo::roles::list_user_roles(&pool, user.user_id)
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "list_user_roles", "err": e.to_string() }),
            )
        })?;

    let permissions = repo::permissions::list_user_permissions(&pool, user.user_id)
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "list_user_permissions", "err": e.to_string() }),
            )
        })?;

    Ok(ApiResponse::ok(MeView {
        user: service::auth::UserView {
            id: user_row.id,
            email: user_row.email,
            phone: user_row.phone,
            display_name: user_row.display_name,
            avatar_url: user_row.avatar_url,
            status: user_row.status,
            created_at: user_row.created_at,
            updated_at: user_row.updated_at,
            row_version: user_row.row_version,
        },
        roles,
        permissions,
    }))
}

fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

fn sha256_hex_bytes(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input);
    let out = hasher.finalize();
    hex::encode(out)
}
