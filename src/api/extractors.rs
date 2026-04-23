use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use gz_core::AppState;
use uuid::Uuid;

use crate::{error, infra, repo};

#[derive(Debug, Clone, Copy)]
pub struct AuthUser {
    pub user_id: Uuid,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = gz_web::AppError;

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
