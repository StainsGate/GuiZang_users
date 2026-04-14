use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RoleRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_by: Option<Uuid>,
    pub row_version: i64,
}

#[derive(Debug, Clone)]
pub struct CreateRole {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_by: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct UpdateRole {
    pub name: Option<String>,
    pub description: Option<String>,
    pub updated_by: Option<Uuid>,
    pub expected_row_version: i64,
}

pub async fn list(pool: &PgPool) -> Result<Vec<RoleRow>, sqlx::Error> {
    sqlx::query_as::<_, RoleRow>(
        r#"
        select *
        from roles
        where deleted_at is null
        order by name asc
        "#,
    )
    .fetch_all(pool)
    .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<RoleRow>, sqlx::Error> {
    sqlx::query_as::<_, RoleRow>(
        r#"
        select *
        from roles
        where id = $1 and deleted_at is null
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn insert<'e, E>(ex: E, input: CreateRole) -> Result<RoleRow, sqlx::Error>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as::<_, RoleRow>(
        r#"
        insert into roles (
            id, name, description,
            created_at, updated_at, deleted_at,
            created_by, updated_by, row_version
        )
        values (
            $1, $2, $3,
            now(), now(), null,
            $4, $4, 0
        )
        returning *
        "#,
    )
    .bind(input.id)
    .bind(input.name)
    .bind(input.description)
    .bind(input.created_by)
    .fetch_one(ex)
    .await
}

pub async fn update(
    pool: &PgPool,
    id: Uuid,
    input: UpdateRole,
) -> Result<Option<RoleRow>, sqlx::Error> {
    sqlx::query_as::<_, RoleRow>(
        r#"
        update roles
        set
            name = coalesce($2, name),
            description = coalesce($3, description),
            updated_at = now(),
            updated_by = $4,
            row_version = row_version + 1
        where id = $1
          and deleted_at is null
          and row_version = $5
        returning *
        "#,
    )
    .bind(id)
    .bind(input.name)
    .bind(input.description)
    .bind(input.updated_by)
    .bind(input.expected_row_version)
    .fetch_optional(pool)
    .await
}

pub async fn soft_delete(
    pool: &PgPool,
    id: Uuid,
    updated_by: Option<Uuid>,
    expected_row_version: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        r#"
        update roles
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

pub async fn list_user_roles(pool: &PgPool, user_id: Uuid) -> Result<Vec<String>, sqlx::Error> {
    let rows: Vec<(String,)> = sqlx::query_as(
        r#"
        select r.name
        from user_roles ur
        join roles r on r.id = ur.role_id and r.deleted_at is null
        where ur.user_id = $1
        order by r.name asc
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn replace_role_permissions(
    tx: &mut Transaction<'_, Postgres>,
    role_id: Uuid,
    permission_ids: &[Uuid],
    created_by: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        delete from role_permissions
        where role_id = $1
        "#,
    )
    .bind(role_id)
    .execute(&mut **tx)
    .await?;

    for pid in permission_ids {
        sqlx::query(
            r#"
            insert into role_permissions (role_id, permission_id, created_at, created_by)
            values ($1, $2, now(), $3)
            on conflict do nothing
            "#,
        )
        .bind(role_id)
        .bind(*pid)
        .bind(created_by)
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}

pub async fn replace_user_roles(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    role_ids: &[Uuid],
    created_by: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        delete from user_roles
        where user_id = $1
        "#,
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await?;

    for rid in role_ids {
        sqlx::query(
            r#"
            insert into user_roles (user_id, role_id, created_at, created_by)
            values ($1, $2, now(), $3)
            on conflict do nothing
            "#,
        )
        .bind(user_id)
        .bind(*rid)
        .bind(created_by)
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}
