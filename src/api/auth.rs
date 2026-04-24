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
/// 注册请求体。
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
/// 登录请求体。
pub(crate) struct LoginBody {
    /// 登录标识（邮箱或手机号）
    identifier: String,
    /// 密码明文
    password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
/// 刷新令牌请求体。
pub(crate) struct RefreshBody {
    /// 刷新令牌
    refresh_token: String,
}

#[derive(Debug, Deserialize, ToSchema)]
/// 登出请求体。
pub(crate) struct LogoutBody {
    /// 刷新令牌
    refresh_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
/// 当前用户信息响应体（用户信息 + RBAC 信息）。
pub(crate) struct MeView {
    /// 用户信息
    user: service::auth::UserView,
    /// 角色列表
    roles: Vec<String>,
    /// 权限码列表
    permissions: Vec<String>,
}

/// 注册新用户（支持 Idempotency-Key）。
#[utoipa::path(
    post,
    path = "/v1/auth/register",
    tag = "Auth",
    request_body = RegisterBody,
    security(()),
    responses((status = 200, description = "注册成功"))
)]
#[tracing::instrument(
    level = "info",
    name = "api.auth.register",
    skip(state, headers, req),
    fields(op = "auth.register", idempotency_key_present = tracing::field::Empty),
    err
)]
pub(crate) async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterBody>,
) -> Result<Response, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    let jwt_cfg = infra::must_jwt_config(&state).await?;

    let idempotency_key = headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    let request_hash = sha256_hex_register_body(&req);

    if let Some(key) = &idempotency_key {
        tracing::Span::current().record("idempotency_key_present", &tracing::field::display(true));
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

    tracing::info!(
        op = "auth.register",
        trace_id = gz_observe::current_trace_id(),
        user_id = %result.user.id,
        status_code = 200,
        "api response"
    );

    let payload = ApiResponse::ok(result);
    if let Some(key) = idempotency_key {
        let expires_at = Utc::now() + Duration::hours(24);
        let response_body = serde_json::to_value(&payload).map_err(|e| {
            error::with_context(
                error::internal("serialize error"),
                serde_json::json!({ "op": "serialize_register_response", "err": e.to_string() }),
            )
        })?;
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

/// 校验用户凭证并签发一对令牌。
#[utoipa::path(
    post,
    path = "/v1/auth/login",
    tag = "Auth",
    request_body = LoginBody,
    security(()),
    responses((status = 200, description = "登录成功"))
)]
#[tracing::instrument(
    level = "info",
    name = "api.auth.login",
    skip(state, headers, req),
    fields(op = "auth.login"),
    err
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

    tracing::info!(
        op = "auth.login",
        trace_id = gz_observe::current_trace_id(),
        status_code = 200,
        "api response"
    );
    Ok(ApiResponse::ok(tokens))
}

/// 使用 refresh token 轮换并签发新的令牌对。
#[utoipa::path(
    post,
    path = "/v1/auth/refresh",
    tag = "Auth",
    request_body = RefreshBody,
    security(()),
    responses((status = 200, description = "刷新令牌成功"))
)]
#[tracing::instrument(
    level = "info",
    name = "api.auth.refresh",
    skip(state, headers, req),
    fields(op = "auth.refresh"),
    err
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

    tracing::info!(
        op = "auth.refresh",
        trace_id = gz_observe::current_trace_id(),
        status_code = 200,
        "api response"
    );
    Ok(ApiResponse::ok(tokens))
}

/// 登出：撤销 refresh token，并使已有 access token 失效。
#[utoipa::path(
    post,
    path = "/v1/auth/logout",
    tag = "Auth",
    request_body = LogoutBody,
    security(()),
    responses((status = 200, description = "登出成功"))
)]
#[tracing::instrument(
    level = "info",
    name = "api.auth.logout",
    skip(state, req),
    fields(op = "auth.logout"),
    err
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
    tracing::info!(
        op = "auth.logout",
        trace_id = gz_observe::current_trace_id(),
        status_code = 200,
        "api response"
    );
    Ok(ApiResponse::<()>::empty_ok())
}

/// 获取当前用户信息与 RBAC 信息。
#[utoipa::path(
    get,
    path = "/v1/auth/me",
    tag = "Auth",
    responses((status = 200, description = "获取当前用户信息"))
)]
#[tracing::instrument(level = "info", name = "api.auth.me", skip(state), fields(op = "auth.me", user_id = %user.user_id), err)]
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

    tracing::info!(
        op = "auth.me",
        trace_id = gz_observe::current_trace_id(),
        status_code = 200,
        roles_len = roles.len(),
        permissions_len = permissions.len(),
        "api response"
    );

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

/// 从请求头读取 User-Agent（用于 refresh token 记录审计字段）。
fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

/// 计算 register 请求体的幂等性哈希（避免对请求体做二次 JSON 序列化）。
fn sha256_hex_register_body(req: &RegisterBody) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();

    hasher.update(b"email:");
    match req.email.as_deref() {
        Some(v) => hasher.update(v.trim().as_bytes()),
        None => hasher.update(b"<none>"),
    }

    hasher.update(b";phone:");
    match req.phone.as_deref() {
        Some(v) => hasher.update(v.trim().as_bytes()),
        None => hasher.update(b"<none>"),
    }

    hasher.update(b";password:");
    hasher.update(req.password.as_bytes());

    hasher.update(b";display_name:");
    hasher.update(req.display_name.trim().as_bytes());

    hex::encode(hasher.finalize())
}
