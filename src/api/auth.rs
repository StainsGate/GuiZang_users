use axum::{
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
use utoipa::ToSchema;

use crate::{api::extractors::AuthUser, error, infra, repo, service};

/// 认证与会话 API 路由（注册/登录/刷新/登出/当前用户）。
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub(crate) struct RegisterBody {
    /// 邮箱（可选，邮箱或手机号至少提供一个）
    email: Option<String>,
    /// 手机号（可选，邮箱或手机号至少提供一个）
    phone: Option<String>,
    /// 密码明文
    password: String,
    /// 显示名称
    display_name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct LoginBody {
    /// 登录标识（邮箱或手机号）
    identifier: String,
    /// 密码明文
    password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct RefreshBody {
    /// 刷新令牌
    refresh_token: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct LogoutBody {
    /// 刷新令牌
    refresh_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct MeView {
    /// 用户信息
    user: service::auth::UserView,
    /// 角色列表
    roles: Vec<String>,
    /// 权限码列表
    permissions: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/v1/auth/register",
    tag = "Auth",
    request_body = RegisterBody,
    security(()),
    responses((status = 200, description = "注册成功"))
)]
pub(crate) async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterBody>,
) -> Result<Response, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    let jwt_cfg = infra::must_jwt_config(&state).await?;

    let request_bytes =
        serde_json::to_vec(&req).map_err(|_| error::bad_request("invalid register body"))?;

    let idempotency_key = headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    let request_hash = sha256_hex_bytes(&request_bytes);

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

#[utoipa::path(
    post,
    path = "/v1/auth/login",
    tag = "Auth",
    request_body = LoginBody,
    security(()),
    responses((status = 200, description = "登录成功"))
)]
pub(crate) async fn login(
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

#[utoipa::path(
    post,
    path = "/v1/auth/refresh",
    tag = "Auth",
    request_body = RefreshBody,
    security(()),
    responses((status = 200, description = "刷新令牌成功"))
)]
pub(crate) async fn refresh(
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

#[utoipa::path(
    post,
    path = "/v1/auth/logout",
    tag = "Auth",
    request_body = LogoutBody,
    security(()),
    responses((status = 200, description = "登出成功"))
)]
pub(crate) async fn logout(
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

#[utoipa::path(
    get,
    path = "/v1/auth/me",
    tag = "Auth",
    responses((status = 200, description = "获取当前用户信息"))
)]
pub(crate) async fn me(
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
