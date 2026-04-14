use axum::{routing::get, Router};
use gz_core::AppState;
use gz_web::ApiResponse;

mod auth;
mod extractors;
mod permissions;
mod roles;
mod users;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/ping", get(ping))
        .merge(auth::router())
        .merge(users::router())
        .merge(roles::router())
        .merge(permissions::router())
}

async fn ping() -> ApiResponse<&'static str> {
    ApiResponse::ok("pong")
}
