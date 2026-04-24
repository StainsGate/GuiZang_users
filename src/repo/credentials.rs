use chrono::{DateTime, Duration, Utc};
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
/// user_credentials 表的一行记录（用户敏感认证信息）。
pub struct CredentialRow {
    /// 用户 ID（主键）。
    pub user_id: Uuid,
    /// 密码哈希（Argon2）。
    pub password_hash: String,
    /// 密码更新时间。
    pub password_updated_at: DateTime<Utc>,
    /// 连续登录失败次数。
    pub failed_login_count: i32,
    /// 锁定截止时间（可选）。
    pub locked_until: Option<DateTime<Utc>>,
    /// 创建时间。
    pub created_at: DateTime<Utc>,
    /// 更新时间。
    pub updated_at: DateTime<Utc>,
    /// 乐观锁版本号。
    pub row_version: i64,
}

/// 按用户 ID 查询凭证记录。
pub async fn get_by_user_id(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<CredentialRow>, sqlx::Error> {
    sqlx::query_as::<_, CredentialRow>(
        r#"
        select *
        from user_credentials
        where user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

/// 插入用户凭证记录（保存密码哈希）。
pub async fn insert<'e, E>(
    ex: E,
    user_id: Uuid,
    password_hash: String,
) -> Result<CredentialRow, sqlx::Error>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as::<_, CredentialRow>(
        r#"
        insert into user_credentials (
            user_id, password_hash, password_updated_at,
            failed_login_count, locked_until,
            created_at, updated_at, row_version
        )
        values (
            $1, $2, now(),
            0, null,
            now(), now(), 0
        )
        returning *
        "#,
    )
    .bind(user_id)
    .bind(password_hash)
    .fetch_one(ex)
    .await
}

/// 记录一次登录失败，必要时锁定账号。
pub async fn on_login_failed(
    pool: &PgPool,
    user_id: Uuid,
    lock_threshold: i32,
    lock_duration: Duration,
) -> Result<CredentialRow, sqlx::Error> {
    let locked_until = Utc::now() + lock_duration;

    sqlx::query_as::<_, CredentialRow>(
        r#"
        update user_credentials
        set
            failed_login_count = failed_login_count + 1,
            locked_until = case
                when failed_login_count + 1 >= $2 then $3
                else locked_until
            end,
            updated_at = now(),
            row_version = row_version + 1
        where user_id = $1
        returning *
        "#,
    )
    .bind(user_id)
    .bind(lock_threshold)
    .bind(locked_until)
    .fetch_one(pool)
    .await
}

/// 记录一次登录成功（清空失败计数并解锁）。
pub async fn on_login_succeeded(pool: &PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        update user_credentials
        set failed_login_count = 0,
            locked_until = null,
            updated_at = now(),
            row_version = row_version + 1
        where user_id = $1
        "#,
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}
