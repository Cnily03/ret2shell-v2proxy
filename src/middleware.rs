use axum::{
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::{
    models::{Claims, ProxyContext},
    AppState,
};

pub struct AuthMiddleware;

impl AuthMiddleware {
    pub async fn scope_admin_required(
        State(state): State<Arc<AppState>>,
        Path(params): Path<std::collections::HashMap<String, String>>,
        request: Request<Body>,
        next: Next,
    ) -> Result<Response, StatusCode> {
        // Extract scope from path
        let namespace = params
            .get("namespace")
            .map(String::as_str)
            .unwrap_or("library");
        let repository = params.get("repository").map(String::as_str).unwrap_or("_");
        if repository == "_" {
            return Err(StatusCode::FORBIDDEN);
        }

        let mut request = request;

        // try change namespace from game id to bucket
        let namespace = match state.database.get_game_by_namespace(namespace).await {
            Ok(Some(game)) => {
                debug!("Game found by namespace: {}", namespace);
                if namespace != game.bucket {
                    info!("Translate namespace {} -> {}", namespace, game.bucket);
                    let uri = request.uri();
                    let new_uri = uri
                        .path_and_query()
                        .map(|pq| pq.as_str())
                        .unwrap_or(uri.path())
                        .replace(
                            &format!("/v2/{}/{}/", namespace, repository),
                            &format!("/v2/{}/{}/", game.bucket, repository),
                        );

                    // change request uri
                    debug!("Modify uri: {} -> {}", uri.path(), new_uri);
                    *request.uri_mut() = axum::http::Uri::try_from(new_uri).unwrap();
                    game.bucket
                } else {
                    namespace.to_string()
                }
            }
            Ok(None) => {
                debug!("No game found by namespace: {}", namespace);
                return Err(StatusCode::FORBIDDEN);
            }
            Err(e) => {
                error!("Error fetching game by namespace: {}", e);
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
        };

        let repo = format!("{}/{}", namespace, repository);
        debug!("Checking scope admin permission for scope: {}", repo);

        // Special handling for library scope
        if namespace == "library" {
            return Self::library_access_required(State(state), Path(params), request, next).await;
        }

        // Check JWT token
        let auth_header = request.headers().get("authorization");
        if let Some(auth_header) = auth_header {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..];

                    // Verify JWT token
                    let mut validation = Validation::default();
                    validation.validate_aud = false; // Don't validate audience

                    match decode::<Claims>(
                        token,
                        &DecodingKey::from_secret(state.config.auth.signing_key.as_ref()),
                        &validation,
                    ) {
                        Ok(token_data) => {
                            debug!("JWT token verified for user: {}", token_data.claims.sub);

                            // Check if user has permission for this scope
                            let has_scope_permission =
                                token_data.claims.access.iter().any(|access| {
                                    access.name.starts_with(&format!("{}/", repo))
                                        || access.name == repo
                                });

                            if !has_scope_permission {
                                warn!(
                                    "User '{}' does not have permission for scope: {}",
                                    token_data.claims.sub, repo
                                );
                                return Err(StatusCode::FORBIDDEN);
                            }

                            debug!(
                                "Scope permission verified for user: {}",
                                token_data.claims.sub
                            );

                            // Add user context to request extensions
                            let proxy_context = ProxyContext {
                                account: token_data.claims.sub.clone(),
                                repo: repo.clone(),
                            };
                            request.extensions_mut().insert(proxy_context);

                            return Ok(next.run(request).await);
                        }
                        Err(e) => {
                            warn!("JWT token verification failed: {}", e);
                            return Err(StatusCode::UNAUTHORIZED);
                        }
                    }
                }
            }
        }

        // No valid JWT token - reject all access
        warn!("No valid authentication for scope: {}", repo);
        Err(StatusCode::UNAUTHORIZED)
    }

    pub async fn library_access_required(
        State(state): State<Arc<AppState>>,
        Path(params): Path<std::collections::HashMap<String, String>>,
        request: Request<Body>,
        next: Next,
    ) -> Result<Response, StatusCode> {
        let method = request.method().clone();
        let repository = params.get("repository").map(String::as_str).unwrap_or("_");
        if repository == "_" {
            return Err(StatusCode::FORBIDDEN);
        }

        let mut request = request;
        // if no namespace, add 'library' to namespace
        match params.get("namespace") {
            Some(_) => {}
            None => {
                let uri = request.uri();
                let new_uri = uri
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or(uri.path())
                    .replace(
                        &format!("/v2/{}/", repository),
                        &format!("/v2/library/{}/", repository),
                    );

                // change request uri
                debug!("Modify uri: {} -> {}", uri.path(), new_uri);
                *request.uri_mut() = axum::http::Uri::try_from(new_uri).unwrap();
            }
        }

        debug!("Checking library access for repository: {}", repository);

        // Check JWT token
        let auth_header = request.headers().get("authorization");
        if let Some(auth_header) = auth_header {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..];

                    // Verify JWT token
                    let mut validation = Validation::default();
                    validation.validate_aud = false; // Don't validate audience

                    match decode::<Claims>(
                        token,
                        &DecodingKey::from_secret(state.config.auth.signing_key.as_ref()),
                        &validation,
                    ) {
                        Ok(token_data) => {
                            debug!(
                                "JWT token verified for library access, user: {}",
                                token_data.claims.sub
                            );

                            // Check if user has permission for library operations
                            let has_library_permission =
                                token_data.claims.access.iter().any(|access| {
                                    access.name.starts_with("library/") || access.name == "library"
                                });

                            if !has_library_permission {
                                warn!(
                                    "User '{}' does not have permission for library",
                                    token_data.claims.sub
                                );
                                return Err(StatusCode::FORBIDDEN);
                            }

                            // For write operations, check if user has push permission
                            if method != "GET" && method != "HEAD" {
                                let has_push_permission =
                                    token_data.claims.access.iter().any(|access| {
                                        (access.name.starts_with("library/")
                                            || access.name == "library")
                                            && access.actions.contains(&"push".to_string())
                                    });

                                if !has_push_permission {
                                    warn!(
                                        "User '{}' does not have push permission for library",
                                        token_data.claims.sub
                                    );
                                    return Err(StatusCode::FORBIDDEN);
                                }
                            }

                            debug!(
                                "Library permission verified for user: {}",
                                token_data.claims.sub
                            );

                            // Add user context to request extensions
                            let proxy_context = ProxyContext {
                                account: token_data.claims.sub.clone(),
                                repo: format!("library/{}", repository),
                            };
                            request.extensions_mut().insert(proxy_context);

                            return Ok(next.run(request).await);
                        }
                        Err(e) => {
                            warn!("JWT token verification failed for library: {}", e);
                            return Err(StatusCode::UNAUTHORIZED);
                        }
                    }
                }
            }
        }

        // No valid JWT token - reject all library access
        warn!("No valid authentication for library access");
        Err(StatusCode::UNAUTHORIZED)
    }
}
