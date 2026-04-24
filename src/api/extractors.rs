use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use gz_core::AppState;
use uuid::Uuid;

use crate::{error, infra, repo};

#[derive(Debug, Clone, Copy)]
/// 从 `Authorization: Bearer <token>` 提取并校验后的已认证用户信息。
pub struct AuthUser {
    /// 用户 ID。
    pub user_id: Uuid,
}

impl FromRequestParts<AppState> for AuthUser {
    /// 认证失败时返回的统一错误类型。
    type Rejection = gz_web::AppError;

    /// 从请求头解析 Bearer token，校验 JWT，并按 session_version 做服务端撤销检查。
    #[tracing::instrument(
        level = "debug",
        name = "auth.extract_user",
        skip(parts, state),
        fields(op = "auth.extract_user", user_id = tracing::field::Empty)
    )]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| error::unauthorized("missing authorization"))?;

        let token = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
            .ok_or_else(|| error::unauthorized("invalid authorization"))?;

        let cfg = infra::must_jwt_config(state).await?;
        let (user_id, token_session_version) = infra::jwt::verify_access_token(token, cfg.as_ref())
            .map_err(|_| error::unauthorized("invalid token"))?;
        tracing::Span::current().record("user_id", &tracing::field::display(user_id));

        let pool = infra::must_pool(state).await?;
        let current = repo::users::get_session_version(&pool, user_id)
            .await
            .map_err(|e| {
                error::with_context(
                    error::internal("db error"),
                    serde_json::json!({ "op": "get_session_version", "user_id": user_id, "err": e.to_string() }),
                )
            })?
            .ok_or_else(|| error::unauthorized("invalid token"))?;

        if current != token_session_version {
            return Err(error::unauthorized("invalid token"));
        }

        Ok(Self { user_id })
    }
}
