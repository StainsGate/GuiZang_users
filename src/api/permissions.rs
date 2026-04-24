use axum::{extract::State, routing::get, Router};
use gz_core::AppState;
use gz_web::ApiResponse;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{api::extractors::AuthUser, error, infra, repo, service};

/// 权限查询 API 路由（RBAC 保护）。
pub fn router() -> Router<AppState> {
    Router::new().route("/permissions", get(list_permissions))
}

#[derive(Debug, Serialize, ToSchema)]
/// 权限视图（对外输出）。
pub(crate) struct PermissionView {
    /// 权限 ID
    id: Uuid,
    /// 权限码（例如 users.read）
    code: String,
    /// 权限描述（可选）
    description: Option<String>,
    /// 乐观锁版本号（row_version）
    row_version: i64,
}

/// 查询权限列表（需要 permissions.read 权限）。
#[utoipa::path(
    get,
    path = "/v1/permissions",
    tag = "Permissions",
    responses((status = 200, description = "查询权限列表"))
)]
pub(crate) async fn list_permissions(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<ApiResponse<Vec<PermissionView>>, gz_web::AppError> {
    let pool = infra::must_pool(&state).await?;
    service::rbac::require_permission(&pool, user.user_id, "permissions.read").await?;

    let rows = repo::permissions::list(&pool).await.map_err(|e| {
        error::with_context(
            error::internal("db error"),
            serde_json::json!({ "op": "list_permissions", "err": e.to_string() }),
        )
    })?;

    Ok(ApiResponse::ok(
        rows.into_iter()
            .map(|p| PermissionView {
                id: p.id,
                code: p.code,
                description: p.description,
                row_version: p.row_version,
            })
            .collect(),
    ))
}
