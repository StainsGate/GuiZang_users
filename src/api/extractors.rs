use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use gz_core::AppState;
use uuid::Uuid;

use crate::{error, infra};

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
        let user_id = infra::jwt::verify_access_token(token, cfg.as_ref())
            .map_err(|_| error::unauthorized("invalid token"))?;

        Ok(Self { user_id })
    }
}
