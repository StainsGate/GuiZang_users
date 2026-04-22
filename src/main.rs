use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, Router};
use gz_core::{App, AppConfig, AppState, CoreError};
use gz_observe::{init_tracing, init_tracing_with_otel, TracingConfig};
use gz_web::{middleware, swagger::SwaggerRouterExt, ApiResponse, RouterAppStateExt};
use serde::Deserialize;
use sqlx::{postgres::PgPoolOptions, PgPool};

mod api;
mod error;
mod infra;
mod repo;
mod service;

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    tracing::info!(trace_id = gz_observe::current_trace_id(), "health");
    ApiResponse::ok(format!("ok (addr={})", state.config.server.addr))
}

#[derive(Debug, thiserror::Error)]
#[error("missing env: {0}")]
struct MissingEnv(&'static str);

#[tokio::main]
async fn main() -> Result<(), CoreError> {
    let (cfg, env) = AppConfig::load()?;
    ensure_app_env(&env);
    apply_otel_env_from_config(&cfg);

    let tracing_cfg = TracingConfig::from_env();
    let _otel_guard = if otel_enabled() {
        Some(init_tracing_with_otel(tracing_cfg).map_err(|e| {
            CoreError::serve(std::io::Error::other(format!("init otel failed: {e}")))
        })?)
    } else {
        let _ = init_tracing(tracing_cfg);
        None
    };

    tracing::info!(otel_enabled = otel_enabled(), "service starting");

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
        .nest("/v1", api::router())
        .with_swagger_ui::<api::ApiDoc>("/v1/swagger-ui/");
    let router = router.with_app_state(state);
    let router = middleware::apply(router, middleware::MiddlewareConfig::default());

    App::new()
        .with_config_and_env(cfg, env)
        .with_router(router)
        .run()
        .await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct OtelConfig {
    enabled: Option<bool>,
    exporter_otlp_endpoint: Option<String>,
    service_name: Option<String>,
}

fn ensure_app_env(env: &gz_core::Environment) {
    if std::env::var("APP_ENV")
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
    {
        return;
    }

    std::env::set_var("APP_ENV", env.as_str());
}

fn apply_otel_env_from_config(cfg: &AppConfig) {
    let otel = cfg
        .extra
        .get("otel")
        .and_then(|v| serde_json::from_value::<OtelConfig>(v.clone()).ok());

    let Some(otel) = otel else { return };

    let enabled = otel.enabled.unwrap_or(false)
        || otel
            .exporter_otlp_endpoint
            .as_deref()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);

    if !enabled {
        return;
    }

    if !std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
    {
        if let Some(v) = otel.exporter_otlp_endpoint {
            if !v.trim().is_empty() {
                std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", v);
            }
        }
    }

    if !std::env::var("OTEL_SERVICE_NAME")
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
    {
        if let Some(v) = otel.service_name {
            if !v.trim().is_empty() {
                std::env::set_var("OTEL_SERVICE_NAME", v);
            }
        }
    }
}

fn otel_enabled() -> bool {
    std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
        || std::env::var("APP_OTEL_ENABLED")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
}
