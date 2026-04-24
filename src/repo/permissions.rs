use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
/// permissions 表的一行记录（软删除记录默认在查询中被过滤）。
pub struct PermissionRow {
    /// 权限 ID。
    pub id: Uuid,
    /// 权限码（唯一）。
    pub code: String,
    /// 权限描述（可选）。
    pub description: Option<String>,
    /// 创建时间。
    pub created_at: DateTime<Utc>,
    /// 更新时间。
    pub updated_at: DateTime<Utc>,
    /// 软删除时间（非空表示已删除）。
    pub deleted_at: Option<DateTime<Utc>>,
    /// 乐观锁版本号。
    pub row_version: i64,
}

/// 查询权限列表（软删除权限不会返回）。
pub async fn list(pool: &PgPool) -> Result<Vec<PermissionRow>, sqlx::Error> {
    sqlx::query_as::<_, PermissionRow>(
        r#"
        select *
        from permissions
        where deleted_at is null
        order by code asc
        "#,
    )
    .fetch_all(pool)
    .await
}

/// 判断用户是否具备指定权限码。
pub async fn has_permission(
    pool: &PgPool,
    user_id: Uuid,
    permission_code: &str,
) -> Result<bool, sqlx::Error> {
    let exists: Option<(bool,)> = sqlx::query_as(
        r#"
        select true as "exists!"
        from user_roles ur
        join roles r on r.id = ur.role_id and r.deleted_at is null
        join role_permissions rp on rp.role_id = r.id
        join permissions p on p.id = rp.permission_id and p.deleted_at is null
        where ur.user_id = $1 and p.code = $2
        limit 1
        "#,
    )
    .bind(user_id)
    .bind(permission_code)
    .fetch_optional(pool)
    .await?;

    Ok(exists.is_some())
}

/// 查询用户拥有的权限码列表。
pub async fn list_user_permissions(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    let rows: Vec<(String,)> = sqlx::query_as(
        r#"
        select distinct p.code
        from user_roles ur
        join roles r on r.id = ur.role_id and r.deleted_at is null
        join role_permissions rp on rp.role_id = r.id
        join permissions p on p.id = rp.permission_id and p.deleted_at is null
        where ur.user_id = $1
        order by p.code asc
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.0).collect())
}
