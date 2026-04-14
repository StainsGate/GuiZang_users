use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, Router};
use gz_core::{App, AppConfig, AppState, CoreError};
use gz_observe::{init_tracing, TracingConfig};
use gz_web::{middleware, ApiResponse, RouterAppStateExt};
use sqlx::{postgres::PgPoolOptions, PgPool};

mod api;
mod error;
mod infra;
mod repo;
mod service;

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    ApiResponse::ok(format!("ok (addr={})", state.config.server.addr))
}

#[derive(Debug, thiserror::Error)]
#[error("missing env: {0}")]
struct MissingEnv(&'static str);

#[tokio::main]
async fn main() -> Result<(), CoreError> {
    let _ = init_tracing(TracingConfig::from_env());

    let (cfg, env) = AppConfig::load()?;
    let state = AppState::new(Arc::new(cfg.clone()));

    let database_url = cfg
        .db
        .url
        .clone()
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .ok_or_else(|| CoreError::serve(MissingEnv("db.url or DATABASE_URL")))?;
    let max_connections: u32 = cfg.db.max_connections;

    let pool: PgPool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(&database_url)
        .await
        .map_err(CoreError::serve)?;

    let jwt_cfg = infra::JwtConfig::from_app_config(&cfg).map_err(CoreError::serve)?;
    state.insert(pool).await;
    state.insert(jwt_cfg).await;

    let router: Router<AppState> = Router::new()
        .route("/health", get(health))
        .nest("/v1", api::router());
    let router = router.with_app_state(state);
    let router = middleware::apply(router, middleware::MiddlewareConfig::default());

    App::new()
        .with_config_and_env(cfg, env)
        .with_router(router)
        .run()
        .await?;
    Ok(())
}
