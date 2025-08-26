use anyhow::{anyhow, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use uuid::Uuid;

use crate::models::{AccessEntry, AuthRequest, AuthResponse, Claims, User};

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| anyhow!("Failed to parse password hash: {}", e))?;
    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn generate_token(
    user: &User,
    auth_request: &AuthRequest,
    signing_key: &str,
) -> Result<AuthResponse> {
    let now = Utc::now();
    let exp = now + Duration::seconds(300); // 5 minutes

    let mut access = Vec::new();

    if let Some(scope) = &auth_request.scope {
        let parts: Vec<&str> = scope.split(':').collect();
        if parts.len() >= 3 {
            let resource_type = parts[0]; // "repository"
            let resource_name = parts[1]; // scope/image or library/image
            let actions: Vec<String> = parts[2].split(',').map(|s| s.to_string()).collect();

            access.push(AccessEntry {
                r#type: resource_type.to_string(),
                name: resource_name.to_string(),
                actions,
            });
        }
    }

    let claims = Claims {
        sub: user.account.clone(),
        iss: "ret2shell-v2-proxy".to_string(),
        aud: auth_request.service.clone().unwrap_or_default(),
        exp: exp.timestamp() as usize,
        nbf: now.timestamp() as usize,
        iat: now.timestamp() as usize,
        jti: Uuid::new_v4().to_string(),
        access,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(signing_key.as_ref()),
    )?;

    Ok(AuthResponse {
        token: token.clone(),
        access_token: token,
        expires_in: 300,
        issued_at: now.to_rfc3339(),
    })
}

pub fn parse_basic_auth(auth_header: &str) -> Option<(String, String)> {
    if !auth_header.starts_with("Basic ") {
        return None;
    }

    let encoded = &auth_header[6..];
    let decoded = general_purpose::STANDARD.decode(encoded).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;

    let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
    if parts.len() == 2 {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None
    }
}
