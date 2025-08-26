use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub auth: AuthConfig,
    pub cluster: ClusterConfig,
    pub database: DatabaseConfig,
    pub server: ServerConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub signing_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterConfig {
    pub registry: RegistryConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegistryConfig {
    pub enabled: bool,
    pub insecure: bool,
    pub server: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub ssl_mode: String,
    pub user: String,
    pub password: String,
    pub db: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: String,
}

impl Config {
    pub async fn load() -> Result<Self> {
        // Try to load from current directory first
        let mut config: Config = if Path::new("config.toml").exists() {
            let content = fs::read_to_string("config.toml").await?;
            toml::from_str(&content)?
        } else if Path::new("/etc/ret2shell/config.toml").exists() {
            // Try to load from /etc/ret2shell/config.toml
            let content = fs::read_to_string("/etc/ret2shell/config.toml").await?;
            toml::from_str(&content)?
        } else {
            anyhow::bail!(
                "Config file not found in current directory or /etc/ret2shell/config.toml"
            );
        };

        // Override with environment variables if specified
        if let Ok(server_port) = std::env::var("LISTEN_PORT") {
            config.server.port = server_port;
        }

        Ok(config)
    }

    pub fn database_url(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}?sslmode={}",
            self.database.user,
            self.database.password,
            self.database.host,
            self.database.port,
            self.database.db,
            self.database.ssl_mode
        )
    }

    pub fn registry_url(&self) -> String {
        let protocol = if self.cluster.registry.insecure {
            "http"
        } else {
            "https"
        };
        format!("{}://{}", protocol, self.cluster.registry.server)
    }
}
