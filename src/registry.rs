use anyhow::Result;
use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode},
};
use reqwest::Client;
use std::sync::Arc;
use tracing::{debug, error, info};

use crate::{models::ProxyContext, AppState};

pub async fn proxy_request(
    state: Arc<AppState>,
    request: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let registry_url = state.config.registry_url();
    let path = request.uri().path();
    let query = request.uri().query().unwrap_or("");

    let target_url = if query.is_empty() {
        format!("{}{}", registry_url, path)
    } else {
        format!("{}{}?{}", registry_url, path, query)
    };

    let method = request.method().clone();
    let headers = request.headers().clone();

    // Extract user context from request extensions (clone it before consuming request)
    let user_context = request.extensions().get::<ProxyContext>().cloned();

    info!(
        method = %method,
        path = %path,
        context = ?user_context,
        "Proxying request"
    );

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| {
            error!("Failed to create HTTP client: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Convert axum::Body to bytes
    let body_bytes = match axum::body::to_bytes(request.into_body(), usize::MAX).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to read request body: {}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    debug!("Request body size: {} bytes", body_bytes.len());

    // Create the proxied request
    let reqwest_method = match method {
        Method::GET => reqwest::Method::GET,
        Method::POST => reqwest::Method::POST,
        Method::PUT => reqwest::Method::PUT,
        Method::DELETE => reqwest::Method::DELETE,
        Method::HEAD => reqwest::Method::HEAD,
        Method::PATCH => reqwest::Method::PATCH,
        Method::OPTIONS => reqwest::Method::OPTIONS,
        _ => reqwest::Method::GET,
    };

    let mut proxy_request = client.request(reqwest_method, &target_url).body(body_bytes);

    // Copy important headers, but be selective
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();

        // Skip certain headers that should not be forwarded
        if matches!(
            name_str.as_str(),
            "host" | "connection" | "transfer-encoding" | "upgrade" | "proxy-connection" | "te"
        ) {
            continue;
        }

        // Forward authorization headers (but they should be JWT tokens for backend)
        if let Ok(value_str) = value.to_str() {
            proxy_request = proxy_request.header(name.as_str(), value_str);
        }
    }

    // Execute the request
    let response = match proxy_request.send().await {
        Ok(resp) => resp,
        Err(e) => {
            error!("Failed to proxy request to registry: {}", e);
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    let status_code = response.status();

    // Log response headers for debugging
    debug!(
        status = %status_code,
        headers = ?response.headers(),
        context = ?user_context,
        "Response details"
    );

    // Convert the response
    let mut response_headers = HeaderMap::new();

    for (name, value) in response.headers().iter() {
        let name_str = name.as_str();
        let value_bytes = value.as_bytes();

        // Skip headers that shouldn't be forwarded
        if matches!(
            name_str.to_lowercase().as_str(),
            "connection" | "transfer-encoding" | "upgrade" | "proxy-connection" | "te"
        ) {
            continue;
        }

        if let Ok(header_value) = HeaderValue::from_bytes(value_bytes) {
            if let Ok(header_name) = name_str.parse::<axum::http::HeaderName>() {
                response_headers.insert(header_name, header_value);
            }
        }
    }

    let body_bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to read response body: {}", e);
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    debug!("Response body size: {} bytes", body_bytes.len());

    // Convert reqwest::StatusCode to axum::http::StatusCode
    let axum_status =
        StatusCode::from_u16(status_code.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut response_builder = Response::builder().status(axum_status);

    for (name, value) in response_headers.iter() {
        response_builder = response_builder.header(name, value);
    }

    match response_builder.body(Body::from(body_bytes)) {
        Ok(response) => {
            // debug!("Successfully proxied request");
            Ok(response)
        }
        Err(e) => {
            error!("Failed to build response: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
