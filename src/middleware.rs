use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::sync::Arc;
use tracing::{debug, warn};

use crate::{
    models::{Claims, ProxyContext},
    AppState,
};

pub struct AuthMiddleware;

impl AuthMiddleware {
    pub async fn scope_admin_required(
        State(state): State<Arc<AppState>>,
        request: Request<Body>,
        next: Next,
    ) -> Result<Response, StatusCode> {
        // Extract scope from path
        let path = request.uri().path();
        let segments: Vec<&str> = path.split('/').collect();

        if segments.len() < 4 {
            warn!("Invalid path format: {}", path);
            return Err(StatusCode::NOT_FOUND);
        }

        // For /v2/{namespace}/{repository}/... structure
        let namespace = segments[2];
        let repository = segments[3];
        let scope = format!("{}/{}", namespace, repository);
        debug!("Checking scope admin permission for scope: {}", scope);

        // Special handling for library scope
        if namespace == "library" {
            return Self::library_access_required(State(state), request, next).await;
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
                                    access.name.starts_with(&format!("{}/", scope))
                                        || access.name == scope
                                });

                            if !has_scope_permission {
                                warn!(
                                    "User '{}' does not have permission for scope: {}",
                                    token_data.claims.sub, scope
                                );
                                return Err(StatusCode::FORBIDDEN);
                            }

                            debug!(
                                "Scope permission verified for user: {}",
                                token_data.claims.sub
                            );

                            // Add user context to request extensions
                            let mut request = request;
                            let user_context = ProxyContext {
                                account: token_data.claims.sub.clone(),
                                scope: scope.clone(),
                            };
                            request.extensions_mut().insert(user_context);

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
        warn!("No valid authentication for scope: {}", scope);
        Err(StatusCode::UNAUTHORIZED)
    }

    pub async fn library_access_required(
        State(state): State<Arc<AppState>>,
        request: Request<Body>,
        next: Next,
    ) -> Result<Response, StatusCode> {
        let method = request.method();
        debug!("Checking library access for method: {}", method);

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
                            let mut request = request;
                            let user_context = ProxyContext {
                                account: token_data.claims.sub.clone(),
                                scope: "library".to_string(),
                            };
                            request.extensions_mut().insert(user_context);

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
