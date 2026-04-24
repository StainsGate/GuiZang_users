use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
/// refresh_tokens 表的一行记录（仅存 token_hash，不存明文）。
pub struct RefreshTokenRow {
    /// 刷新令牌记录 ID。
    pub id: Uuid,
    /// 用户 ID。
    pub user_id: Uuid,
    /// 刷新令牌哈希（SHA-256 hex）。
    pub token_hash: String,
    /// 签发时间。
    pub issued_at: DateTime<Utc>,
    /// 过期时间。
    pub expires_at: DateTime<Utc>,
    /// 撤销时间（可选）。
    pub revoked_at: Option<DateTime<Utc>>,
    /// 轮换后的新令牌 ID（可选）。
    pub replaced_by: Option<Uuid>,
    /// IP（可选）。
    pub ip: Option<String>,
    /// User-Agent（可选）。
    pub user_agent: Option<String>,
    /// 创建时间。
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
/// 新建刷新令牌记录的入参。
pub struct NewRefreshToken {
    /// 刷新令牌记录 ID。
    pub id: Uuid,
    /// 用户 ID。
    pub user_id: Uuid,
    /// 刷新令牌哈希（SHA-256 hex）。
    pub token_hash: String,
    /// 签发时间。
    pub issued_at: DateTime<Utc>,
    /// 过期时间。
    pub expires_at: DateTime<Utc>,
    /// IP（可选）。
    pub ip: Option<String>,
    /// User-Agent（可选）。
    pub user_agent: Option<String>,
}

/// 插入一条刷新令牌记录。
pub async fn insert<'e, E>(ex: E, input: NewRefreshToken) -> Result<RefreshTokenRow, sqlx::Error>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as::<_, RefreshTokenRow>(
        r#"
        insert into refresh_tokens (
            id, user_id, token_hash, issued_at, expires_at,
            revoked_at, replaced_by, ip, user_agent, created_at
        )
        values ($1, $2, $3, $4, $5, null, null, $6, $7, now())
        returning *
        "#,
    )
    .bind(input.id)
    .bind(input.user_id)
    .bind(input.token_hash)
    .bind(input.issued_at)
    .bind(input.expires_at)
    .bind(input.ip)
    .bind(input.user_agent)
    .fetch_one(ex)
    .await
}

/// 通过 token_hash 查询刷新令牌记录。
pub async fn get_by_hash(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<RefreshTokenRow>, sqlx::Error> {
    sqlx::query_as::<_, RefreshTokenRow>(
        r#"
        select *
        from refresh_tokens
        where token_hash = $1
        limit 1
        "#,
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await
}

/// 撤销指定刷新令牌记录。
pub async fn revoke(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    revoke_in(pool, id).await
}

/// 在指定执行器中撤销刷新令牌记录（事务内使用）。
pub async fn revoke_in<'e, E>(ex: E, id: Uuid) -> Result<(), sqlx::Error>
where
    E: PgExecutor<'e>,
{
    sqlx::query(
        r#"
        update refresh_tokens
        set revoked_at = now()
        where id = $1 and revoked_at is null
        "#,
    )
    .bind(id)
    .execute(ex)
    .await?;
    Ok(())
}

/// 在指定执行器中轮换刷新令牌：撤销旧记录并标记 replaced_by。
pub async fn rotate_in<'e, E>(ex: E, old_id: Uuid, new_id: Uuid) -> Result<(), sqlx::Error>
where
    E: PgExecutor<'e>,
{
    sqlx::query(
        r#"
        update refresh_tokens
        set revoked_at = now(),
            replaced_by = $2
        where id = $1 and revoked_at is null
        "#,
    )
    .bind(old_id)
    .bind(new_id)
    .execute(ex)
    .await?;

    Ok(())
}

/// 撤销用户所有未撤销的刷新令牌记录。
pub async fn revoke_all_for_user(pool: &PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
    revoke_all_for_user_in(pool, user_id).await
}

/// 在指定执行器中撤销用户所有未撤销的刷新令牌记录（事务内使用）。
pub async fn revoke_all_for_user_in<'e, E>(ex: E, user_id: Uuid) -> Result<(), sqlx::Error>
where
    E: PgExecutor<'e>,
{
    sqlx::query(
        r#"
        update refresh_tokens
        set revoked_at = now()
        where user_id = $1 and revoked_at is null
        "#,
    )
    .bind(user_id)
    .execute(ex)
    .await?;

    Ok(())
}
