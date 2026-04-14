use sqlx::PgPool;
use uuid::Uuid;

use crate::{error, repo};

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
                serde_json::json!({ "op": "has_permission", "err": e.to_string() }),
            )
        })?;

    if ok {
        Ok(())
    } else {
        Err(error::forbidden("forbidden"))
    }
}
