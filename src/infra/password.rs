use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand_core::OsRng;

#[derive(Debug)]
/// 密码哈希/校验相关错误。
pub struct PasswordError {
    /// 错误信息。
    pub message: String,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PasswordError {}

/// 使用 Argon2 对明文密码进行哈希（带随机 salt）。
pub fn hash_password(plain: &str) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map_err(|e| PasswordError {
            message: e.to_string(),
        })?
        .to_string();
    Ok(hash)
}

/// 校验明文密码是否与存储的 Argon2 哈希匹配。
pub fn verify_password(plain: &str, password_hash: &str) -> Result<bool, PasswordError> {
    let parsed = PasswordHash::new(password_hash).map_err(|e| PasswordError {
        message: e.to_string(),
    })?;
    Ok(Argon2::default()
        .verify_password(plain.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let hash = hash_password("p@ssw0rd").unwrap();
        assert!(verify_password("p@ssw0rd", &hash).unwrap());
        assert!(!verify_password("wrong", &hash).unwrap());
    }
}
