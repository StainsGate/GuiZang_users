use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub email: Option<String>,
    pub email_normalized: Option<String>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub phone: Option<String>,
    pub phone_verified_at: Option<DateTime<Utc>>,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub status: String,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub updated_by: Option<Uuid>,
    pub row_version: i64,
}

#[derive(Debug, Clone)]
pub struct CreateUser {
    pub id: Uuid,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub status: String,
    pub created_by: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct UpdateUser {
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub status: Option<String>,
    pub updated_by: Option<Uuid>,
    pub expected_row_version: i64,
}

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
