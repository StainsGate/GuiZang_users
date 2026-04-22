use axum::{
    extract::{Path, State},
    routing::{get, put},
    Json, Router,
};
use gz_core::AppState;
use gz_web::ApiResponse;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{api::extractors::AuthUser, error, infra, repo, service};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/roles", get(list_roles).post(create_role))
        .route(
            "/roles/{id}",
            get(get_role).patch(update_role).delete(delete_role),
        )
        .route("/roles/{id}/permissions", put(replace_role_permissions))
        .route("/users/{id}/roles", put(replace_user_roles))
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct CreateRoleBody {
    /// 角色名称
    name: String,
    /// 角色描述（可选）
    description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct UpdateRoleBody {
    /// 角色名称（可选）
    name: Option<String>,
    /// 角色描述（可选）
    description: Option<String>,
    /// 乐观锁版本号（row_version）
    row_version: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct ReplaceRolePermissionsBody {
    /// 权限 ID 列表
    permission_ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct ReplaceUserRolesBody {
    /// 角色 ID 列表
    role_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RoleView {
    /// 角色 ID
    id: Uuid,
    /// 角色名称
    name: String,
    /// 角色描述（可选）
    description: Option<String>,
    /// 乐观锁版本号（row_version）
    row_version: i64,
}

#[utoipa::path(
    get,
    path = "/v1/roles",
    tag = "Roles",
    responses((status = 200, description = "查询角色列表"))
)]
pub(crate) async fn list_roles(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<ApiResponse<Vec<RoleView>>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    service::rbac::require_permission(&pool, user.user_id, "roles.manage").await?;

    let rows = repo::roles::list(&pool).await.map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "list_roles", "err": e.to_string() }),
        )
    })?;

    Ok(ApiResponse::ok(
        rows.into_iter().map(role_row_to_view).collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/v1/roles",
    tag = "Roles",
    request_body = CreateRoleBody,
    responses((status = 200, description = "创建角色"))
)]
pub(crate) async fn create_role(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateRoleBody>,
) -> Result<ApiResponse<RoleView>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    service::rbac::require_permission(&pool, user.user_id, "roles.manage").await?;

    if req.name.trim().is_empty() {
        return Err(error::bad_request("name is required"));
    }

    let mut tx = pool.begin().await.map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "begin", "err": e.to_string() }),
        )
    })?;

    let row = repo::roles::insert(
        &mut *tx,
        repo::roles::CreateRole {
            id: Uuid::new_v4(),
            name: req.name,
            description: req.description,
            created_by: Some(user.user_id),
        },
    )
    .await
    .map_err(map_insert_role_error)?;

    tx.commit().await.map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "commit", "err": e.to_string() }),
        )
    })?;

    Ok(ApiResponse::ok(role_row_to_view(row)))
}

#[utoipa::path(
    get,
    path = "/v1/roles/{id}",
    params(
        ("id" = Uuid, Path, description = "Role id")
    ),
    tag = "Roles",
    responses((status = 200, description = "查询角色详情"))
)]
pub(crate) async fn get_role(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<ApiResponse<RoleView>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    service::rbac::require_permission(&pool, user.user_id, "roles.manage").await?;

    let row = repo::roles::get_by_id(&pool, id)
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "get_role_by_id", "err": e.to_string() }),
            )
        })?
        .ok_or_else(|| error::not_found("role not found"))?;

    Ok(ApiResponse::ok(role_row_to_view(row)))
}

#[utoipa::path(
    patch,
    path = "/v1/roles/{id}",
    params(
        ("id" = Uuid, Path, description = "Role id")
    ),
    tag = "Roles",
    request_body = UpdateRoleBody,
    responses((status = 200, description = "更新角色"))
)]
pub(crate) async fn update_role(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateRoleBody>,
) -> Result<ApiResponse<RoleView>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    service::rbac::require_permission(&pool, user.user_id, "roles.manage").await?;

    let updated = repo::roles::update(
        &pool,
        id,
        repo::roles::UpdateRole {
            name: req.name,
            description: req.description,
            updated_by: Some(user.user_id),
            expected_row_version: req.row_version,
        },
    )
    .await
    .map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "update_role", "err": e.to_string() }),
        )
    })?
    .ok_or_else(|| error::conflict("row_version mismatch or role not found"))?;

    Ok(ApiResponse::ok(role_row_to_view(updated)))
}

#[utoipa::path(
    delete,
    path = "/v1/roles/{id}",
    params(
        ("id" = Uuid, Path, description = "Role id")
    ),
    tag = "Roles",
    request_body = UpdateRoleBody,
    responses((status = 200, description = "删除角色（软删除）"))
)]
pub(crate) async fn delete_role(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateRoleBody>,
) -> Result<ApiResponse<()>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    service::rbac::require_permission(&pool, user.user_id, "roles.manage").await?;

    let ok = repo::roles::soft_delete(&pool, id, Some(user.user_id), req.row_version)
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "delete_role", "err": e.to_string() }),
            )
        })?;

    if ok {
        Ok(ApiResponse::<()>::empty_ok())
    } else {
        Err(error::conflict("row_version mismatch or role not found"))
    }
}

#[utoipa::path(
    put,
    path = "/v1/roles/{id}/permissions",
    params(
        ("id" = Uuid, Path, description = "Role id")
    ),
    tag = "Roles",
    request_body = ReplaceRolePermissionsBody,
    responses((status = 200, description = "替换角色权限"))
)]
pub(crate) async fn replace_role_permissions(
    State(state): State<AppState>,
    user: AuthUser,
    Path(role_id): Path<Uuid>,
    Json(req): Json<ReplaceRolePermissionsBody>,
) -> Result<ApiResponse<()>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    service::rbac::require_permission(&pool, user.user_id, "roles.manage").await?;

    let mut tx = pool.begin().await.map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "begin", "err": e.to_string() }),
        )
    })?;

    repo::roles::replace_role_permissions(
        &mut tx,
        role_id,
        &req.permission_ids,
        Some(user.user_id),
    )
    .await
    .map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "replace_role_permissions", "err": e.to_string() }),
        )
    })?;

    tx.commit().await.map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "commit", "err": e.to_string() }),
        )
    })?;

    Ok(ApiResponse::<()>::empty_ok())
}

#[utoipa::path(
    put,
    path = "/v1/users/{id}/roles",
    params(
        ("id" = Uuid, Path, description = "User id")
    ),
    tag = "Roles",
    request_body = ReplaceUserRolesBody,
    responses((status = 200, description = "替换用户角色"))
)]
pub(crate) async fn replace_user_roles(
    State(state): State<AppState>,
    user: AuthUser,
    Path(target_user_id): Path<Uuid>,
    Json(req): Json<ReplaceUserRolesBody>,
) -> Result<ApiResponse<()>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    service::rbac::require_permission(&pool, user.user_id, "roles.manage").await?;

    let mut tx = pool.begin().await.map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "begin", "err": e.to_string() }),
        )
    })?;

    repo::roles::replace_user_roles(&mut tx, target_user_id, &req.role_ids, Some(user.user_id))
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "replace_user_roles", "err": e.to_string() }),
            )
        })?;

    tx.commit().await.map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "commit", "err": e.to_string() }),
        )
    })?;

    Ok(ApiResponse::<()>::empty_ok())
}

fn role_row_to_view(r: repo::roles::RoleRow) -> RoleView {
    RoleView {
        id: r.id,
        name: r.name,
        description: r.description,
        row_version: r.row_version,
    }
}

fn map_insert_role_error(e: sqlx::Error) -> gz_web::AppError {
    match &e {
        sqlx::Error::Database(db) => {
            let code = db.code().unwrap_or_default().to_string();
            if code == "23505" {
                return error::bad_request("role name already exists");
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
