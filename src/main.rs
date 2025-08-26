mod auth;
mod config;
mod database;
mod handlers;
mod middleware;
mod models;
mod registry;

use anyhow::Result;
use axum::{
    middleware::from_fn_with_state,
    routing::{any, get},
    Router,
};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{info, Level};
use tracing_subscriber;

use crate::{
    config::Config,
    database::Database,
    handlers::{auth_handler, health_check, proxy_handler, registry_v2_check},
    middleware::AuthMiddleware,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    info!("Starting ret2shell-v2-proxy server...");

    // Load configuration
    let config = Config::load().await?;
    info!("Configuration loaded successfully");

    // Check if registry is enabled
    if !config.cluster.registry.enabled {
        tracing::error!("Registry is disabled in configuration. Exiting.");
        std::process::exit(1);
    }

    // Initialize database connection
    let database = Database::new(&config.database).await?;
    info!("Database connection established");

    // Create shared state
    let app_state = Arc::new(AppState {
        config: config.clone(),
        database,
    });

    // Build the application
    let app = build_app(app_state).await;

    // Start the server
    let listener =
        tokio::net::TcpListener::bind(format!("{}:{}", config.server.host, config.server.port))
            .await?;

    info!(
        "Server listening on {}:{}",
        config.server.host, config.server.port
    );

    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub database: Database,
}

async fn build_app(state: Arc<AppState>) -> Router {
    Router::new()
        // Health check endpoint
        .route("/health", get(health_check))
        // Docker registry v2 API endpoints
        .route("/v2/", get(registry_v2_check))
        .route("/v2/token", get(auth_handler))
        // Registry operations with scope-based authentication
        .route(
            "/v2/{namespace}/{repository}/manifests/{reference}",
            any(proxy_handler).layer(from_fn_with_state(
                state.clone(),
                AuthMiddleware::scope_admin_required,
            )),
        )
        .route(
            "/v2/{namespace}/{repository}/blobs/{digest}",
            any(proxy_handler).layer(from_fn_with_state(
                state.clone(),
                AuthMiddleware::scope_admin_required,
            )),
        )
        .route(
            "/v2/{namespace}/{repository}/blobs/uploads/",
            any(proxy_handler).layer(from_fn_with_state(
                state.clone(),
                AuthMiddleware::scope_admin_required,
            )),
        )
        .route(
            "/v2/{namespace}/{repository}/blobs/uploads/{uuid}",
            any(proxy_handler).layer(from_fn_with_state(
                state.clone(),
                AuthMiddleware::scope_admin_required,
            )),
        )
        // Library operations with library-specific authentication
        .route(
            "/v2/library/manifests/{reference}",
            any(proxy_handler).layer(from_fn_with_state(
                state.clone(),
                AuthMiddleware::library_access_required,
            )),
        )
        .route(
            "/v2/library/blobs/{digest}",
            any(proxy_handler).layer(from_fn_with_state(
                state.clone(),
                AuthMiddleware::library_access_required,
            )),
        )
        .route(
            "/v2/library/blobs/uploads/",
            any(proxy_handler).layer(from_fn_with_state(
                state.clone(),
                AuthMiddleware::library_access_required,
            )),
        )
        .route(
            "/v2/library/blobs/uploads/{uuid}",
            any(proxy_handler).layer(from_fn_with_state(
                state.clone(),
                AuthMiddleware::library_access_required,
            )),
        )
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive()),
        )
        .with_state(state)
}
