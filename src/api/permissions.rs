use axum::{extract::State, routing::get, Router};
use gz_core::AppState;
use gz_web::ApiResponse;
use serde::Serialize;
use uuid::Uuid;

use crate::{api::extractors::AuthUser, error, infra, repo, service};

pub fn router() -> Router<AppState> {
    Router::new().route("/permissions", get(list_permissions))
}

#[derive(Debug, Serialize)]
struct PermissionView {
    id: Uuid,
    code: String,
    description: Option<String>,
    row_version: i64,
}

async fn list_permissions(
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
