use anyhow::Result;
use axum::{
    body::Body,
    http::{uri, HeaderMap, HeaderValue, Method, Request, Response, StatusCode},
};
use reqwest::Client;
use std::sync::Arc;
use tracing::{debug, error, info};

use crate::{models::ProxyContext, AppState};

fn infer_origin(headers: &HeaderMap) -> Result<String> {
    let mut scheme = "http".to_string();
    let mut host = "".to_string();

    // directly return if x-forwarded-origin is present
    if let Some(origin) = headers
        .get("x-forwarded-origin")
        .and_then(|v| v.to_str().ok())
    {
        return Ok(origin.to_string());
    }

    // infer scheme and host

    if let Some(s) = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
    {
        scheme = s.to_string();
    }

    if let Some(h) = headers.get("host").and_then(|v| v.to_str().ok()) {
        host = h.to_string();
    }

    if let Some(h) = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
    {
        host = h.to_string();
    }

    if let Some(uri_str) = headers.get("x-forwarded-uri").and_then(|v| v.to_str().ok()) {
        if let Ok(u) = uri::Uri::try_from(uri_str) {
            if let Some(s) = u.scheme_str() {
                scheme = s.to_string();
            }
            if let Some(h) = u.host() {
                host = h.to_string();
            }
        }
    }

    if !host.is_empty() {
        return Ok(format!("{}://{}", scheme, host));
    }

    Err(anyhow::anyhow!("Cannot extract host from request headers"))
}

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
    let proxy_context = request.extensions().get::<ProxyContext>().cloned();
    info!(
        method = %method,
        path = %path,
        context = ?proxy_context,
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
        context = ?proxy_context,
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

        // Replace header location with the original request origin
        if name_str.eq_ignore_ascii_case("location") {
            let loc = value.to_str().map_err(|e| {
                error!("Invalid location header value: {}", e);
                StatusCode::BAD_GATEWAY
            })?;
            let origin = infer_origin(&headers).map_err(|e| {
                error!("Failed to infer origin from request: {}", e);
                StatusCode::BAD_REQUEST
            })?;
            let new_location = match uri::Uri::try_from(loc) {
                Ok(u) => {
                    let path_and_query = u.path_and_query().map_or("", |pq| pq.as_str());
                    format!("{}{}", origin, path_and_query)
                }
                Err(_) => {
                    // If location is a relative path, just prepend the origin
                    let p = if loc.starts_with('/') {
                        loc.to_string()
                    } else {
                        format!("/{}", loc)
                    };
                    format!("{}{}", origin, p)
                }
            };
            if let Ok(new_value) = HeaderValue::from_str(&new_location) {
                response_headers.insert(name.clone(), new_value);
            }
            continue;
        }

        if let Ok(header_value) = HeaderValue::from_bytes(value_bytes) {
            if let Ok(header_name) = name_str.parse::<axum::http::HeaderName>() {
                response_headers.insert(header_name, header_value);
            }
        }
    }

    debug!(
        headers = ?response_headers,
        "Response headers processed"
    );

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
