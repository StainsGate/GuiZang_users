use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use gz_core::AppState;
use gz_web::ApiResponse;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{api::extractors::AuthUser, error, infra, repo, service};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users", get(list_users).post(create_user))
        .route("/users/{id}", get(get_user).patch(update_user))
        .route("/users/{id}/delete", post(delete_user))
}

#[derive(Debug, Deserialize)]
pub(crate) struct UsersQuery {
    email: Option<String>,
    phone: Option<String>,
    status: Option<String>,
    limit: Option<i64>,
    after_created_at: Option<String>,
    after_id: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct UsersListView {
    /// 用户列表
    items: Vec<service::auth::UserView>,
    /// 下一页游标：created_at（RFC3339）
    next_after_created_at: Option<DateTime<Utc>>,
    /// 下一页游标：id
    next_after_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct CreateUserBody {
    /// 邮箱（可选，邮箱或手机号至少提供一个）
    email: Option<String>,
    /// 手机号（可选，邮箱或手机号至少提供一个）
    phone: Option<String>,
    /// 显示名称
    display_name: String,
    /// 头像 URL
    avatar_url: Option<String>,
    /// 状态（例如 active/disabled）
    status: Option<String>,
    /// 初始密码（可选）
    password: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct UpdateUserBody {
    /// 显示名称（可选）
    display_name: Option<String>,
    /// 头像 URL（可选）
    avatar_url: Option<String>,
    /// 状态（可选，例如 active/disabled）
    status: Option<String>,
    /// 乐观锁版本号（row_version）
    row_version: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct DeleteUserBody {
    /// 乐观锁版本号（row_version）
    row_version: i64,
}

#[utoipa::path(
    get,
    path = "/v1/users",
    tag = "Users",
    responses((status = 200, description = "查询用户列表"))
)]
pub(crate) async fn list_users(
    State(state): State<AppState>,
    user: AuthUser,
    Query(q): Query<UsersQuery>,
) -> Result<ApiResponse<UsersListView>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    service::rbac::require_permission(&pool, user.user_id, "users.read").await?;

    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let after_created_at = q
        .after_created_at
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let email_normalized = q.email.as_ref().map(|v| v.trim().to_ascii_lowercase());
    let phone = q.phone.as_ref().map(|v| v.trim().to_string());

    let rows = repo::users::list(
        &pool,
        limit,
        after_created_at,
        q.after_id,
        email_normalized.as_deref(),
        phone.as_deref(),
        q.status.as_deref(),
    )
    .await
    .map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "list_users", "err": e.to_string() }),
        )
    })?;

    let next = rows.last().map(|u| (u.created_at, u.id));

    Ok(ApiResponse::ok(UsersListView {
        items: rows.into_iter().map(user_row_to_view).collect(),
        next_after_created_at: next.map(|n| n.0),
        next_after_id: next.map(|n| n.1),
    }))
}

#[utoipa::path(
    post,
    path = "/v1/users",
    tag = "Users",
    request_body = CreateUserBody,
    responses((status = 200, description = "创建用户"))
)]
pub(crate) async fn create_user(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateUserBody>,
) -> Result<ApiResponse<service::auth::UserView>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    service::rbac::require_permission(&pool, user.user_id, "users.write").await?;

    let email = req
        .email
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let phone = req
        .phone
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    if email.is_none() && phone.is_none() {
        return Err(error::bad_request("email or phone is required"));
    }
    if req.display_name.trim().is_empty() {
        return Err(error::bad_request("display_name is required"));
    }

    let mut tx = pool.begin().await.map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "begin", "err": e.to_string() }),
        )
    })?;

    let user_id = Uuid::new_v4();
    let row = repo::users::insert(
        &mut *tx,
        repo::users::CreateUser {
            id: user_id,
            email,
            phone,
            display_name: req.display_name,
            avatar_url: req.avatar_url,
            status: req.status.unwrap_or_else(|| "active".to_string()),
            created_by: Some(user.user_id),
        },
    )
    .await
    .map_err(|e| map_insert_user_error(e))?;

    if let Some(pw) = req.password {
        if !pw.is_empty() {
            let hash = infra::password::hash_password(&pw)
                .map_err(|_| error::internal("password hash error"))?;
            repo::credentials::insert(&mut *tx, user_id, hash)
                .await
                .map_err(|e| {
                    error::with_context(
                        error::internal("db error"),
                        serde_json::json!({ "op": "insert_credentials", "err": e.to_string() }),
                    )
                })?;
        }
    }

    tx.commit().await.map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "commit", "err": e.to_string() }),
        )
    })?;

    Ok(ApiResponse::ok(user_row_to_view(row)))
}

#[utoipa::path(
    get,
    path = "/v1/users/{id}",
    params(
        ("id" = Uuid, Path, description = "User id")
    ),
    tag = "Users",
    responses((status = 200, description = "查询用户详情"))
)]
pub(crate) async fn get_user(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<ApiResponse<service::auth::UserView>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    service::rbac::require_permission(&pool, user.user_id, "users.read").await?;

    let row = repo::users::get_by_id(&pool, id)
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "get_user_by_id", "err": e.to_string() }),
            )
        })?
        .ok_or_else(|| error::not_found("user not found"))?;

    Ok(ApiResponse::ok(user_row_to_view(row)))
}

#[utoipa::path(
    patch,
    path = "/v1/users/{id}",
    params(
        ("id" = Uuid, Path, description = "User id")
    ),
    tag = "Users",
    request_body = UpdateUserBody,
    responses((status = 200, description = "更新用户"))
)]
pub(crate) async fn update_user(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateUserBody>,
) -> Result<ApiResponse<service::auth::UserView>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    service::rbac::require_permission(&pool, user.user_id, "users.write").await?;

    let updated = repo::users::update(
        &pool,
        id,
        repo::users::UpdateUser {
            display_name: req.display_name,
            avatar_url: req.avatar_url,
            status: req.status,
            updated_by: Some(user.user_id),
            expected_row_version: req.row_version,
        },
    )
    .await
    .map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "update_user", "err": e.to_string() }),
        )
    })?
    .ok_or_else(|| error::conflict("row_version mismatch or user not found"))?;

    Ok(ApiResponse::ok(user_row_to_view(updated)))
}

#[utoipa::path(
    post,
    path = "/v1/users/{id}/delete",
    params(
        ("id" = Uuid, Path, description = "User id")
    ),
    tag = "Users",
    request_body = DeleteUserBody,
    responses((status = 200, description = "删除用户（软删除）"))
)]
pub(crate) async fn delete_user(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<DeleteUserBody>,
) -> Result<ApiResponse<()>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    service::rbac::require_permission(&pool, user.user_id, "users.write").await?;

    let ok = repo::users::soft_delete(&pool, id, Some(user.user_id), req.row_version)
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "delete_user", "err": e.to_string() }),
            )
        })?;

    if ok {
        Ok(ApiResponse::<()>::empty_ok())
    } else {
        Err(error::conflict("row_version mismatch or user not found"))
    }
}

fn user_row_to_view(u: repo::users::UserRow) -> service::auth::UserView {
    service::auth::UserView {
        id: u.id,
        email: u.email,
        phone: u.phone,
        display_name: u.display_name,
        avatar_url: u.avatar_url,
        status: u.status,
        created_at: u.created_at,
        updated_at: u.updated_at,
        row_version: u.row_version,
    }
}

fn map_insert_user_error(e: sqlx::Error) -> gz_web::AppError {
    match &e {
        sqlx::Error::Database(db) => {
            let code = db.code().unwrap_or_default().to_string();
            if code == "23505" {
                return error::bad_request("email or phone already exists");
            }
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "err": e.to_string() }),
            )
        }
        _ => error::with_context(
            error::internal("db error"),
            serde_json::json!({ "err": e.to_string() }),
        ),
    }
}
