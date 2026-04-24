use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgExecutor, PgPool};

#[derive(Debug, Clone, sqlx::FromRow)]
/// idempotency_records 表的一行记录（按 scope+key 去重）。
pub struct IdempotencyRecordRow {
    /// 幂等作用域（例如 "auth.register"）。
    pub scope: String,
    /// 幂等键（来自请求头 Idempotency-Key）。
    pub key: String,
    /// 请求内容哈希（用于检测同 key 不同请求体的冲突）。
    pub request_hash: String,
    /// 原始响应状态码。
    pub status_code: i32,
    /// 原始响应体（JSON）。
    pub response_body: Value,
    /// 创建时间。
    pub created_at: DateTime<Utc>,
    /// 过期时间（超过该时间不再视为命中）。
    pub expires_at: DateTime<Utc>,
}

/// 获取仍在有效期内的幂等记录。
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

/// 插入幂等记录（若已存在同 scope+key 则忽略）。
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
