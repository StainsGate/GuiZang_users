use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::infra::JwtConfig;

#[derive(Debug, Serialize, Deserialize)]
/// Access token 的 JWT claims。
pub struct AccessClaims {
    /// 用户 ID（UUID 字符串）。
    pub sub: String,
    /// 签发时间（Unix timestamp）。
    pub iat: i64,
    /// 过期时间（Unix timestamp）。
    pub exp: i64,
    /// 会话版本号（用于登出后立即失效 access token）。
    pub sv: i64,
}

/// 签发 access token（JWT）。
pub fn sign_access_token(
    user_id: Uuid,
    session_version: i64,
    cfg: &JwtConfig,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp();
    let exp = now + cfg.access_ttl_seconds;

    let claims = AccessClaims {
        sub: user_id.to_string(),
        iat: now,
        exp,
        sv: session_version,
    };

    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&cfg.secret),
    )
}

/// 校验 access token（JWT），成功返回 `(user_id, session_version)`。
pub fn verify_access_token(
    token: &str,
    cfg: &JwtConfig,
) -> Result<(Uuid, i64), jsonwebtoken::errors::Error> {
    let mut validation = Validation::default();
    validation.validate_exp = true;

    let data = jsonwebtoken::decode::<AccessClaims>(
        token,
        &DecodingKey::from_secret(&cfg.secret),
        &validation,
    )?;

    let user_id = Uuid::parse_str(&data.claims.sub).map_err(|_| {
        jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken)
    })?;

    Ok((user_id, data.claims.sv))
}

#[cfg(test)]
/// JWT 签发与校验的自检用例。
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    /// 基本 roundtrip：签发后可解析出相同 user_id 与 session_version。
    fn jwt_roundtrip() {
        let cfg = JwtConfig {
            secret: Arc::from(b"test-secret".to_vec()),
            access_ttl_seconds: 60,
            refresh_ttl_seconds: 3600,
        };

        let user_id = Uuid::new_v4();
        let token = sign_access_token(user_id, 7, &cfg).unwrap();
        let (parsed_id, parsed_sv) = verify_access_token(&token, &cfg).unwrap();
        assert_eq!(parsed_id, user_id);
        assert_eq!(parsed_sv, 7);
    }
}
