use std::sync::Arc;

use gz_core::{AppConfig, AppState};
use gz_web::AppError;
use serde_json::Value;
use sqlx::PgPool;

pub mod jwt;
pub mod password;

#[derive(Clone)]
pub struct JwtConfig {
    pub secret: Arc<[u8]>,
    pub access_ttl_seconds: i64,
    pub refresh_ttl_seconds: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum InfraError {
    #[error("missing env: {0}")]
    MissingEnv(&'static str),

    #[error("invalid env: {0}")]
    InvalidEnv(&'static str),
}

impl JwtConfig {
    pub fn from_app_config(cfg: &AppConfig) -> Result<Self, InfraError> {
        let secret = read_secret(cfg)
            .or_else(|| std::env::var("JWT_SECRET").ok())
            .ok_or(InfraError::MissingEnv("jwt_secret or JWT_SECRET"))?;

        if secret.is_empty() {
            return Err(InfraError::InvalidEnv("jwt_secret or JWT_SECRET"));
        }

        let access_ttl_seconds = std::env::var("ACCESS_TOKEN_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(900);

        let refresh_ttl_seconds = std::env::var("REFRESH_TOKEN_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60 * 60 * 24 * 30);

        Ok(Self {
            secret: Arc::from(secret.into_bytes()),
            access_ttl_seconds,
            refresh_ttl_seconds,
        })
    }
}

pub async fn must_pool(state: &AppState) -> Result<PgPool, AppError> {
    state
        .get::<PgPool>()
        .await
        .map(|p| (*p).clone())
        .ok_or_else(|| AppError::internal("missing PgPool in AppState"))
}

pub async fn must_jwt_config(state: &AppState) -> Result<Arc<JwtConfig>, AppError> {
    state
        .get::<JwtConfig>()
        .await
        .ok_or_else(|| AppError::internal("missing JwtConfig in AppState"))
}

fn read_secret(cfg: &AppConfig) -> Option<String> {
    cfg.extra.get("jwt_secret").and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        _ => None,
    })
}
