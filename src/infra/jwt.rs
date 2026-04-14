use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::infra::JwtConfig;

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
}

pub fn sign_access_token(
    user_id: Uuid,
    cfg: &JwtConfig,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp();
    let exp = now + cfg.access_ttl_seconds;

    let claims = AccessClaims {
        sub: user_id.to_string(),
        iat: now,
        exp,
    };

    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&cfg.secret),
    )
}

pub fn verify_access_token(
    token: &str,
    cfg: &JwtConfig,
) -> Result<Uuid, jsonwebtoken::errors::Error> {
    let mut validation = Validation::default();
    validation.validate_exp = true;

    let data = jsonwebtoken::decode::<AccessClaims>(
        token,
        &DecodingKey::from_secret(&cfg.secret),
        &validation,
    )?;

    Uuid::parse_str(&data.claims.sub).map_err(|_| {
        jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn jwt_roundtrip() {
        let cfg = JwtConfig {
            secret: Arc::from(b"test-secret".to_vec()),
            access_ttl_seconds: 60,
            refresh_ttl_seconds: 3600,
        };

        let user_id = Uuid::new_v4();
        let token = sign_access_token(user_id, &cfg).unwrap();
        let parsed = verify_access_token(&token, &cfg).unwrap();
        assert_eq!(parsed, user_id);
    }
}
