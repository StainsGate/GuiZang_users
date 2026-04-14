use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshTokenRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub replaced_by: Option<Uuid>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewRefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

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

pub async fn revoke(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    revoke_in(pool, id).await
}

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
