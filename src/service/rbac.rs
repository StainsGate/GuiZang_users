use sqlx::PgPool;
use uuid::Uuid;

use crate::{error, repo};

/// 要求指定用户具备某个权限码，否则返回 403。
#[tracing::instrument(level = "info", name = "service.rbac.require_permission", skip(pool), fields(op = "rbac.require_permission", user_id = %user_id, permission_code = permission_code))]
pub async fn require_permission(
    pool: &PgPool,
    user_id: Uuid,
    permission_code: &str,
) -> Result<(), gz_web::AppError> {
    let ok = repo::permissions::has_permission(pool, user_id, permission_code)
        .await
        .map_err(|e| {
            error::with_context(
                error::internal("db error"),
                serde_json::json!({ "op": "has_permission", "user_id": user_id, "permission_code": permission_code, "err": e.to_string() }),
            )
        })?;

    if ok {
        Ok(())
    } else {
        Err(error::forbidden("forbidden"))
    }
}
