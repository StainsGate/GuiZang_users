use chrono::{DateTime, Duration, Utc};
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CredentialRow {
    pub user_id: Uuid,
    pub password_hash: String,
    pub password_updated_at: DateTime<Utc>,
    pub failed_login_count: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub row_version: i64,
}

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
