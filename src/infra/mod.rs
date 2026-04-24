use std::sync::Arc;

use gz_core::{AppConfig, AppState};
use gz_web::AppError;
use serde_json::Value;
use sqlx::PgPool;

/// JWT 签名与校验相关实现。
pub mod jwt;
/// 密码哈希与校验相关实现。
pub mod password;

#[derive(Clone)]
/// JWT 配置（密钥与过期时间）。
pub struct JwtConfig {
    /// JWT HMAC 密钥（字节数组）。
    pub secret: Arc<[u8]>,
    /// Access token 有效期（秒）。
    pub access_ttl_seconds: i64,
    /// Refresh token 有效期（秒）。
    pub refresh_ttl_seconds: i64,
}

#[derive(Debug, thiserror::Error)]
/// 基础设施层错误（配置缺失/非法等）。
pub enum InfraError {
    #[error("missing env: {0}")]
    /// 缺少必要配置项。
    MissingEnv(&'static str),

    #[error("invalid env: {0}")]
    /// 配置项存在但内容非法。
    InvalidEnv(&'static str),
}

impl JwtConfig {
    /// 从应用配置与环境变量读取 JWT 配置。
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

/// 从 AppState 中取得 PgPool（缺失则返回内部错误）。
pub async fn must_pool(state: &AppState) -> Result<PgPool, AppError> {
    state
        .get::<PgPool>()
        .await
        .map(|p| (*p).clone())
        .ok_or_else(|| AppError::internal("missing PgPool in AppState"))
}

/// 从 AppState 中取得 JwtConfig（缺失则返回内部错误）。
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
