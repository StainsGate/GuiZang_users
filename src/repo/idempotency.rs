use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgExecutor, PgPool};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IdempotencyRecordRow {
    pub scope: String,
    pub key: String,
    pub request_hash: String,
    pub status_code: i32,
    pub response_body: Value,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub async fn get_valid(
    pool: &PgPool,
    scope: &str,
    key: &str,
) -> Result<Option<IdempotencyRecordRow>, sqlx::Error> {
    sqlx::query_as::<_, IdempotencyRecordRow>(
        r#"
        select *
        from idempotency_records
        where scope = $1 and key = $2 and expires_at > now()
        "#,
    )
    .bind(scope)
    .bind(key)
    .fetch_optional(pool)
    .await
}

pub async fn insert<'e, E>(
    ex: E,
    scope: &str,
    key: &str,
    request_hash: &str,
    status_code: i32,
    response_body: &Value,
    expires_at: DateTime<Utc>,
) -> Result<(), sqlx::Error>
where
    E: PgExecutor<'e>,
{
    sqlx::query(
        r#"
        insert into idempotency_records (
            scope, key, request_hash, status_code, response_body, created_at, expires_at
        )
        values ($1, $2, $3, $4, $5, now(), $6)
        on conflict (scope, key) do nothing
        "#,
    )
    .bind(scope)
    .bind(key)
    .bind(request_hash)
    .bind(status_code)
    .bind(response_body)
    .bind(expires_at)
    .execute(ex)
    .await?;

    Ok(())
}
