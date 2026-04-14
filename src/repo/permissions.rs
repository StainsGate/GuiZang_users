use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PermissionRow {
    pub id: Uuid,
    pub code: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub row_version: i64,
}

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
