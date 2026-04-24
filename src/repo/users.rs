use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
/// users 表的一行记录（软删除记录默认在查询中被过滤）。
pub struct UserRow {
    /// 用户 ID。
    pub id: Uuid,
    /// 邮箱（可选）。
    pub email: Option<String>,
    /// 归一化邮箱（小写），用于唯一约束与查询（可选）。
    pub email_normalized: Option<String>,
    /// 邮箱验证时间（可选）。
    pub email_verified_at: Option<DateTime<Utc>>,
    /// 手机号（可选）。
    pub phone: Option<String>,
    /// 手机号验证时间（可选）。
    pub phone_verified_at: Option<DateTime<Utc>>,
    /// 显示名称。
    pub display_name: String,
    /// 头像 URL（可选）。
    pub avatar_url: Option<String>,
    /// 状态（例如 active/disabled）。
    pub status: String,
    /// 最近登录时间（可选）。
    pub last_login_at: Option<DateTime<Utc>>,
    /// 创建时间。
    pub created_at: DateTime<Utc>,
    /// 更新时间。
    pub updated_at: DateTime<Utc>,
    /// 软删除时间（非空表示已删除）。
    pub deleted_at: Option<DateTime<Utc>>,
    /// 创建人（可选）。
    pub created_by: Option<Uuid>,
    /// 更新人（可选）。
    pub updated_by: Option<Uuid>,
    /// 会话版本号（用于登出后立即使 access token 失效）。
    pub session_version: i64,
    /// 乐观锁版本号。
    pub row_version: i64,
}

#[derive(Debug, Clone)]
/// 创建用户的入参（对应 users 表 insert）。
pub struct CreateUser {
    /// 用户 ID。
    pub id: Uuid,
    /// 邮箱（可选）。
    pub email: Option<String>,
    /// 手机号（可选）。
    pub phone: Option<String>,
    /// 显示名称。
    pub display_name: String,
    /// 头像 URL（可选）。
    pub avatar_url: Option<String>,
    /// 状态（例如 active/disabled）。
    pub status: String,
    /// 创建人（可选）。
    pub created_by: Option<Uuid>,
}

#[derive(Debug, Clone)]
/// 更新用户的入参（对应 users 表 update）。
pub struct UpdateUser {
    /// 显示名称（可选）。
    pub display_name: Option<String>,
    /// 头像 URL（可选）。
    pub avatar_url: Option<String>,
    /// 状态（可选，例如 active/disabled）。
    pub status: Option<String>,
    /// 更新人（可选）。
    pub updated_by: Option<Uuid>,
    /// 期望的乐观锁版本号（row_version）。
    pub expected_row_version: i64,
}

/// 按用户 ID 查询用户（软删除用户不会返回）。
pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as::<_, UserRow>(
        r#"
        select *
        from users
        where id = $1 and deleted_at is null
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// 通过邮箱（归一化）或手机号查询用户（软删除用户不会返回）。
pub async fn get_by_email_or_phone(
    pool: &PgPool,
    email_normalized: Option<&str>,
    phone: Option<&str>,
) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as::<_, UserRow>(
        r#"
        select *
        from users
        where deleted_at is null
          and (
                ($1::text is not null and email_normalized = $1)
             or ($2::text is not null and phone = $2)
          )
        limit 1
        "#,
    )
    .bind(email_normalized)
    .bind(phone)
    .fetch_optional(pool)
    .await
}

/// 查询用户列表（支持游标分页与条件过滤）。
pub async fn list(
    pool: &PgPool,
    limit: i64,
    after_created_at: Option<DateTime<Utc>>,
    after_id: Option<Uuid>,
    email_normalized: Option<&str>,
    phone: Option<&str>,
    status: Option<&str>,
) -> Result<Vec<UserRow>, sqlx::Error> {
    sqlx::query_as::<_, UserRow>(
        r#"
        select *
        from users
        where deleted_at is null
          and ($1::text is null or email_normalized = $1)
          and ($2::text is null or phone = $2)
          and ($3::text is null or status = $3)
          and (
                $4::timestamptz is null
             or (created_at, id) > ($4::timestamptz, $5::uuid)
          )
        order by created_at asc, id asc
        limit $6
        "#,
    )
    .bind(email_normalized)
    .bind(phone)
    .bind(status)
    .bind(after_created_at)
    .bind(after_id.unwrap_or_else(Uuid::nil))
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// 插入一条用户记录。
pub async fn insert<'e, E>(ex: E, input: CreateUser) -> Result<UserRow, sqlx::Error>
where
    E: PgExecutor<'e>,
{
    let email_normalized = input.email.as_ref().map(|e| e.trim().to_ascii_lowercase());

    sqlx::query_as::<_, UserRow>(
        r#"
        insert into users (
            id, email, email_normalized, phone, display_name, avatar_url, status,
            created_at, updated_at, created_by, updated_by, row_version
        )
        values (
            $1, $2, $3, $4, $5, $6, $7,
            now(), now(), $8, $8, 0
        )
        returning *
        "#,
    )
    .bind(input.id)
    .bind(input.email)
    .bind(email_normalized)
    .bind(input.phone)
    .bind(input.display_name)
    .bind(input.avatar_url)
    .bind(input.status)
    .bind(input.created_by)
    .fetch_one(ex)
    .await
}

/// 更新用户记录（基于 row_version 乐观锁），返回更新后的行。
pub async fn update(
    pool: &PgPool,
    id: Uuid,
    input: UpdateUser,
) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as::<_, UserRow>(
        r#"
        update users
        set
            display_name = coalesce($2, display_name),
            avatar_url = coalesce($3, avatar_url),
            status = coalesce($4, status),
            updated_at = now(),
            updated_by = $5,
            row_version = row_version + 1
        where id = $1
          and deleted_at is null
          and row_version = $6
        returning *
        "#,
    )
    .bind(id)
    .bind(input.display_name)
    .bind(input.avatar_url)
    .bind(input.status)
    .bind(input.updated_by)
    .bind(input.expected_row_version)
    .fetch_optional(pool)
    .await
}

/// 更新用户的最后登录时间。
pub async fn touch_last_login(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        update users
        set last_login_at = now(),
            updated_at = now(),
            row_version = row_version + 1
        where id = $1 and deleted_at is null
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// 读取用户的会话版本号（软删除用户不会返回）。
pub async fn get_session_version(pool: &PgPool, id: Uuid) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        select session_version
        from users
        where id = $1 and deleted_at is null
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// 递增用户会话版本号（用于登出后立即失效 access token）。
pub async fn bump_session_version(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    bump_session_version_in(pool, id).await
}

/// 在指定执行器中递增用户会话版本号（事务内使用）。
pub async fn bump_session_version_in<'e, E>(ex: E, id: Uuid) -> Result<bool, sqlx::Error>
where
    E: PgExecutor<'e>,
{
    let r = sqlx::query(
        r#"
        update users
        set session_version = session_version + 1,
            updated_at = now(),
            row_version = row_version + 1
        where id = $1 and deleted_at is null
        "#,
    )
    .bind(id)
    .execute(ex)
    .await?;

    Ok(r.rows_affected() == 1)
}

/// 软删除用户（设置 deleted_at），基于 row_version 乐观锁。
pub async fn soft_delete(
    pool: &PgPool,
    id: Uuid,
    updated_by: Option<Uuid>,
    expected_row_version: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        r#"
        update users
        set deleted_at = now(),
            updated_at = now(),
            updated_by = $2,
            row_version = row_version + 1
        where id = $1
          and deleted_at is null
          and row_version = $3
        "#,
    )
    .bind(id)
    .bind(updated_by)
    .bind(expected_row_version)
    .execute(pool)
    .await?;

    Ok(r.rows_affected() == 1)
}
