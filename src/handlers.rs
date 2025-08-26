use axum::{
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Json, Response},
};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::{
    auth::{generate_token, parse_basic_auth, verify_password},
    models::AuthRequest,
    registry::proxy_request,
    AppState,
};

// Macro to get service name from environment variable
macro_rules! get_service_name {
    () => {
        std::env::var("V2_SERVICE").unwrap_or_else(|_| "ret2shell".to_string())
    };
}

// Helper function to create error responses
fn create_error_response(status: StatusCode, message: &str) -> Response {
    let error_body = serde_json::json!({
        "errors": [{
            "code": match status {
                StatusCode::UNAUTHORIZED => "UNAUTHORIZED",
                StatusCode::FORBIDDEN => "FORBIDDEN",
                StatusCode::NOT_FOUND => "NOT_FOUND",
                StatusCode::BAD_REQUEST => "BAD_REQUEST",
                StatusCode::SERVICE_UNAVAILABLE => "SERVICE_UNAVAILABLE",
                _ => "UNKNOWN"
            },
            "message": message
        }]
    });

    let mut response = Response::new(axum::body::Body::from(error_body.to_string()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("Content-Type", HeaderValue::from_static("application/json"));
    response
}

pub async fn health_check() -> impl IntoResponse {
    let service_name = get_service_name!();
    Json(serde_json::json!({
        "status": "healthy",
        "service": service_name
    }))
}

pub async fn registry_v2_check(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Check if authorization header is present
    if headers.get("authorization").is_none() {
        // Determine protocol and host from headers
        let protocol = if headers
            .get("x-forwarded-proto")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("http")
            == "https"
        {
            "https"
        } else {
            "http"
        };

        let default_host = format!("{}:{}", state.config.server.host, state.config.server.port);
        let host = headers
            .get("x-forwarded-host")
            .or_else(|| headers.get("host"))
            .and_then(|h| h.to_str().ok())
            .unwrap_or(&default_host);

        let realm = format!("{}://{}/v2/token", protocol, host);
        let service_name = get_service_name!();

        let www_auth_value = format!(r#"Bearer realm="{}",service="{}""#, realm, service_name);
        let fallback_value = format!(
            r#"Bearer realm="http://localhost:1331/v2/token",service="{}""#,
            service_name
        );

        // Return 401 with WWW-Authenticate header to trigger Docker auth flow
        let mut response = Response::new(axum::body::Body::empty());
        *response.status_mut() = StatusCode::UNAUTHORIZED;
        response.headers_mut().insert(
            "WWW-Authenticate",
            HeaderValue::from_str(&www_auth_value).unwrap_or_else(|_| {
                HeaderValue::from_str(&fallback_value).unwrap_or_else(|_| {
                    HeaderValue::from_static(
                        r#"Bearer realm="http://localhost:1331/v2/token",service="ret2shell""#,
                    )
                })
            }),
        );
        response.headers_mut().insert(
            "Docker-Distribution-API-Version",
            HeaderValue::from_static("registry/2.0"),
        );
        return response;
    }

    // If auth header is present, return success
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        "Docker-Distribution-API-Version",
        HeaderValue::from_static("registry/2.0"),
    );
    response
}

pub async fn auth_handler(
    State(state): State<Arc<AppState>>,
    Query(auth_req): Query<AuthRequest>,
    headers: HeaderMap,
) -> impl IntoResponse {
    debug!(
        service = auth_req.service,
        scope = auth_req.scope,
        account = auth_req.account,
        "Auth request"
    );

    // Get authorization header
    let auth_header = match headers.get("authorization").and_then(|h| h.to_str().ok()) {
        Some(header) => header,
        None => {
            return create_error_response(StatusCode::UNAUTHORIZED, "Login required");
        }
    };

    // Parse basic auth
    let (username, password) = match parse_basic_auth(auth_header) {
        Some(credentials) => credentials,
        None => {
            return create_error_response(StatusCode::UNAUTHORIZED, "Failed to parse credentials");
        }
    };

    debug!("Authentication attempt for user: {}", username);

    // Get user from database
    let user = match state.database.get_user_by_username(&username).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            warn!("User not found: {}", username);
            return create_error_response(StatusCode::UNAUTHORIZED, "Invalid username or password");
        }
        Err(e) => {
            error!("Database error while getting user: {}", e);
            return create_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Service temporarily unavailable",
            );
        }
    };

    // Verify password
    let password_valid = match verify_password(&password, &user.password) {
        Ok(valid) => valid,
        Err(e) => {
            error!("Password verification error: {}", e);
            return create_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Service temporarily unavailable",
            );
        }
    };

    if !password_valid {
        warn!("Invalid password for user: {}", username);
        return create_error_response(StatusCode::UNAUTHORIZED, "Invalid username or password");
    }

    // Check if user can authenticate
    if !user.can_authenticate() {
        warn!(
            "User {} cannot authenticate (not verified or banned)",
            username
        );
        return create_error_response(
            StatusCode::UNAUTHORIZED,
            "Not verified or banned. Please check your account status.",
        );
    }

    // Check if user can access registry
    if !user.can_access_registry() {
        warn!("User {} does not have Game permission", username);
        return create_error_response(StatusCode::FORBIDDEN, "Access denied");
    }

    // Check scope permissions if specified
    if let Some(scope_str) = &auth_req.scope {
        let scope_parts: Vec<&str> = scope_str.split(':').collect();
        if scope_parts.len() >= 2 {
            let scope_name = scope_parts[1];

            // Parse scope/image format
            let scope_image_parts: Vec<&str> = scope_name.splitn(2, '/').collect();
            if scope_image_parts.len() != 2 {
                warn!("Invalid scope format: {}", scope_name);
                return create_error_response(StatusCode::BAD_REQUEST, "Invalid request format");
            }

            let scope = scope_image_parts[0];
            let image = scope_image_parts[1];

            // Check if image contains '/' (not allowed)
            if image.contains('/') {
                warn!("Image name contains '/', not allowed: {}", image);
                return create_error_response(StatusCode::BAD_REQUEST, "Invalid request format");
            }

            // Special handling for library scope
            if scope == "library" {
                // For library scope, check if user has required permissions
                let actions: Vec<&str> = if scope_parts.len() >= 3 {
                    scope_parts[2].split(',').collect()
                } else {
                    vec![]
                };

                let has_write_action = actions
                    .iter()
                    .any(|&action| action == "push" || action == "pull,push");

                if has_write_action && !user.can_write_library() {
                    warn!(
                        "User {} does not have DevOps permission for library write",
                        username
                    );
                    return create_error_response(StatusCode::UNAUTHORIZED, "Access denied");
                }
            } else {
                // Check if user is admin of the specified game scope
                match state.database.get_game_by_scope(scope).await {
                    Ok(Some(game)) => {
                        if !game.is_admin(user.id) {
                            warn!("User '{}' is not admin of game scope: {}", username, scope);
                            return create_error_response(
                                StatusCode::UNAUTHORIZED,
                                "Access denied",
                            );
                        }
                    }
                    Ok(None) => {
                        warn!(user = username, "Game not found for scope: {}", scope);
                        return create_error_response(StatusCode::UNAUTHORIZED, "Access denied");
                    }
                    Err(e) => {
                        error!("Database error while getting game: {}", e);
                        return create_error_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Service temporarily unavailable",
                        );
                    }
                }
            }
        }
    }

    // Generate token
    let auth_response = match generate_token(&user, &auth_req, &state.config.auth.signing_key) {
        Ok(response) => response,
        Err(e) => {
            error!("Token generation error: {}", e);
            return create_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Service temporarily unavailable",
            );
        }
    };

    info!("Authentication successful for user: {}", username);

    // Return successful response
    let mut response = Response::new(axum::body::Body::from(
        serde_json::to_string(&auth_response).unwrap_or_default(),
    ));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert("Content-Type", HeaderValue::from_static("application/json"));
    response
}

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<impl IntoResponse, StatusCode> {
    let path = request.uri().path();
    let method = request.method();

    debug!("Handling {} request to {}", method, path);

    // Perform the proxy request
    match proxy_request(state, request).await {
        Ok(response) => Ok(response),
        Err(status) => {
            error!("Proxy request failed with status: {}", status);
            Err(status)
        }
    }
}
