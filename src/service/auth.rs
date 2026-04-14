use base64::Engine;
use chrono::{Duration, Utc};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{error, infra, repo};

const ADMIN_ROLE_ID: Uuid = Uuid::from_u128(1);

#[derive(Debug, Clone)]
pub struct RegisterInput {
    pub email: Option<String>,
    pub phone: Option<String>,
    pub password: String,
    pub display_name: String,
}

#[derive(Debug, Clone)]
pub struct LoginInput {
    pub identifier: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct RefreshInput {
    pub refresh_token: String,
}

#[derive(Debug, Clone)]
pub struct LogoutInput {
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub expires_in: i64,
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserView {
    pub id: Uuid,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub status: String,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
    pub row_version: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthResult {
    pub user: UserView,
    pub tokens: TokenPair,
}

pub async fn register(
    pool: &PgPool,
    jwt_cfg: &infra::JwtConfig,
    input: RegisterInput,
    ip: Option<String>,
    user_agent: Option<String>,
) -> Result<AuthResult, gz_web::AppError> {
    let email = input
        .email
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let phone = input
        .phone
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    if email.is_none() && phone.is_none() {
        return Err(error::bad_request("email or phone is required"));
    }
    if input.password.is_empty() {
        return Err(error::bad_request("password is required"));
    }
    if input.display_name.trim().is_empty() {
        return Err(error::bad_request("display_name is required"));
    }

    let password_hash = infra::password::hash_password(&input.password)
        .map_err(|_| error::internal("password hash error"))?;

    let mut tx: Transaction<'_, Postgres> = pool.begin().await.map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "begin", "err": e.to_string() }),
        )
    })?;

    let existing_users: i64 = sqlx::query_scalar(
        r#"
        select count(1)
        from users
        where deleted_at is null
        "#,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "count_users", "err": e.to_string() }),
        )
    })?;
    let is_first_user = existing_users == 0;

    let user_id = Uuid::new_v4();

    let user = repo::users::insert(
        &mut *tx,
        repo::users::CreateUser {
            id: user_id,
            email,
            phone,
            display_name: input.display_name,
            avatar_url: None,
            status: "active".to_string(),
            created_by: None,
        },
    )
    .await
    .map_err(map_insert_user_error)?;

    repo::credentials::insert(&mut *tx, user_id, password_hash)
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "insert_credentials", "err": e.to_string() }),
            )
        })?;

    if is_first_user {
        repo::roles::replace_user_roles(&mut tx, user_id, &[ADMIN_ROLE_ID], None)
            .await
            .map_err(|e| {
                error::with_context(
                    error::internal("db error"),
                    serde_json::json!({ "op": "assign_admin_role", "err": e.to_string() }),
                )
            })?;
    }

    let tokens = issue_tokens_in_tx(&mut tx, jwt_cfg, user_id, ip, user_agent).await?;

    tx.commit().await.map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "commit", "err": e.to_string() }),
        )
    })?;

    Ok(AuthResult {
        user: user_view(user),
        tokens,
    })
}

pub async fn login(
    pool: &PgPool,
    jwt_cfg: &infra::JwtConfig,
    input: LoginInput,
    ip: Option<String>,
    user_agent: Option<String>,
) -> Result<TokenPair, gz_web::AppError> {
    if input.identifier.trim().is_empty() || input.password.is_empty() {
        return Err(error::unauthorized("invalid credentials"));
    }

    let identifier = input.identifier.trim();
    let (email_normalized, phone) = if identifier.contains('@') {
        (Some(identifier.to_ascii_lowercase()), None)
    } else {
        (None, Some(identifier.to_string()))
    };

    let user =
        repo::users::get_by_email_or_phone(pool, email_normalized.as_deref(), phone.as_deref())
            .await
            .map_err(|e| {
                error::with_context(
                    error::internal("db error"),
                    serde_json::json!({ "op": "get_user", "err": e.to_string() }),
                )
            })?
            .ok_or_else(|| error::unauthorized("invalid credentials"))?;

    let cred = repo::credentials::get_by_user_id(pool, user.id)
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "get_credentials", "err": e.to_string() }),
            )
        })?
        .ok_or_else(|| error::unauthorized("invalid credentials"))?;

    if let Some(until) = cred.locked_until {
        if until > Utc::now() {
            return Err(error::unauthorized("account locked"));
        }
    }

    let ok = infra::password::verify_password(&input.password, &cred.password_hash)
        .map_err(|_| error::internal("password verify error"))?;

    if !ok {
        let _ = repo::credentials::on_login_failed(pool, user.id, 5, Duration::minutes(15)).await;
        return Err(error::unauthorized("invalid credentials"));
    }

    repo::credentials::on_login_succeeded(pool, user.id)
        .await
        .ok();
    repo::users::touch_last_login(pool, user.id).await.ok();

    let mut tx: Transaction<'_, Postgres> = pool.begin().await.map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "begin", "err": e.to_string() }),
        )
    })?;

    let tokens = issue_tokens_in_tx(&mut tx, jwt_cfg, user.id, ip, user_agent).await?;

    tx.commit().await.map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "commit", "err": e.to_string() }),
        )
    })?;

    Ok(tokens)
}

pub async fn refresh(
    pool: &PgPool,
    jwt_cfg: &infra::JwtConfig,
    input: RefreshInput,
    ip: Option<String>,
    user_agent: Option<String>,
) -> Result<TokenPair, gz_web::AppError> {
    if input.refresh_token.trim().is_empty() {
        return Err(error::unauthorized("invalid refresh token"));
    }

    let token_hash = sha256_hex(input.refresh_token.trim());
    let existing = repo::refresh_tokens::get_by_hash(pool, &token_hash)
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "get_refresh_token", "err": e.to_string() }),
            )
        })?
        .ok_or_else(|| error::unauthorized("invalid refresh token"))?;

    if existing.revoked_at.is_some() || existing.expires_at <= Utc::now() {
        return Err(error::unauthorized("invalid refresh token"));
    }

    let mut tx: Transaction<'_, Postgres> = pool.begin().await.map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "begin", "err": e.to_string() }),
        )
    })?;

    let new = new_refresh_token(jwt_cfg, existing.user_id, ip, user_agent)?;
    let inserted = repo::refresh_tokens::insert(&mut *tx, new.db.clone())
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "insert_refresh_token", "err": e.to_string() }),
            )
        })?;

    repo::refresh_tokens::rotate_in(&mut *tx, existing.id, inserted.id)
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "rotate_refresh_token", "err": e.to_string() }),
            )
        })?;

    tx.commit().await.map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "commit", "err": e.to_string() }),
        )
    })?;

    let access_token = infra::jwt::sign_access_token(existing.user_id, jwt_cfg)
        .map_err(|_| error::internal("jwt sign error"))?;

    Ok(TokenPair {
        access_token,
        expires_in: jwt_cfg.access_ttl_seconds,
        refresh_token: new.raw_token,
    })
}

pub async fn logout(pool: &PgPool, input: LogoutInput) -> Result<(), gz_web::AppError> {
    if input.refresh_token.trim().is_empty() {
        return Ok(());
    }

    let token_hash = sha256_hex(input.refresh_token.trim());
    if let Some(r) = repo::refresh_tokens::get_by_hash(pool, &token_hash)
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "get_refresh_token", "err": e.to_string() }),
            )
        })?
    {
        let _ = repo::refresh_tokens::revoke(pool, r.id).await;
    }

    Ok(())
}

#[derive(Clone)]
struct NewRefreshTokenWithRaw {
    raw_token: String,
    db: repo::refresh_tokens::NewRefreshToken,
}

fn new_refresh_token(
    cfg: &infra::JwtConfig,
    user_id: Uuid,
    ip: Option<String>,
    user_agent: Option<String>,
) -> Result<NewRefreshTokenWithRaw, gz_web::AppError> {
    let mut bytes = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    let issued_at = Utc::now();
    let expires_at = issued_at + Duration::seconds(cfg.refresh_ttl_seconds);

    Ok(NewRefreshTokenWithRaw {
        raw_token: raw.clone(),
        db: repo::refresh_tokens::NewRefreshToken {
            id: Uuid::new_v4(),
            user_id,
            token_hash: sha256_hex(&raw),
            issued_at,
            expires_at,
            ip,
            user_agent,
        },
    })
}

async fn issue_tokens_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    jwt_cfg: &infra::JwtConfig,
    user_id: Uuid,
    ip: Option<String>,
    user_agent: Option<String>,
) -> Result<TokenPair, gz_web::AppError> {
    let access_token = infra::jwt::sign_access_token(user_id, jwt_cfg)
        .map_err(|_| error::internal("jwt sign error"))?;

    let new = new_refresh_token(jwt_cfg, user_id, ip, user_agent)?;
    repo::refresh_tokens::insert(&mut **tx, new.db)
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "insert_refresh_token", "err": e.to_string() }),
            )
        })?;

    Ok(TokenPair {
        access_token,
        expires_in: jwt_cfg.access_ttl_seconds,
        refresh_token: new.raw_token,
    })
}

fn user_view(user: repo::users::UserRow) -> UserView {
    UserView {
        id: user.id,
        email: user.email,
        phone: user.phone,
        display_name: user.display_name,
        avatar_url: user.avatar_url,
        status: user.status,
        created_at: user.created_at,
        updated_at: user.updated_at,
        row_version: user.row_version,
    }
}

fn map_insert_user_error(e: sqlx::Error) -> gz_web::AppError {
    match &e {
        sqlx::Error::Database(db) => {
            let code = db.code().unwrap_or_default().to_string();
            if code == "23505" {
                return error::bad_request("email or phone already exists");
            }
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "err": e.to_string() }),
            )
        }
        _ => error::with_context(
            error::internal("db error"),
            serde_json::json!({ "err": e.to_string() }),
        ),
    }
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let out = hasher.finalize();
    hex::encode(out)
}
