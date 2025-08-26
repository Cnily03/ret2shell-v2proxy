use crate::{
    config::DatabaseConfig,
    models::{Game, User},
};
use anyhow::Result;
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        let database_url = format!(
            "postgres://{}:{}@{}:{}/{}?sslmode={}",
            config.user, config.password, config.host, config.port, config.db, config.ssl_mode
        );

        let pool = PgPool::connect(&database_url).await?;

        Ok(Database { pool })
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT id, account, nickname, password, email, permissions, hidden, banned
            FROM "user"
            WHERE account = $1 OR email = $1
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn get_user_by_id(&self, user_id: i64) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT id, account, nickname, password, email, permissions, hidden, banned
            FROM "user"
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn get_game_by_namespace(&self, namespace: &str) -> Result<Option<Game>> {
        // First try to parse as ID (all digits)
        if namespace.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(id) = namespace.parse::<i64>() {
                let game = sqlx::query_as::<_, Game>(
                    r#"
                    SELECT id, bucket, admins
                    FROM "game"
                    WHERE id = $1
                    "#,
                )
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;

                if game.is_some() {
                    return Ok(game);
                }
            }
        }

        // Try to find by bucket
        let game = sqlx::query_as::<_, Game>(
            r#"
            SELECT id, bucket, admins
            FROM "game"
            WHERE bucket = $1
            "#,
        )
        .bind(namespace)
        .fetch_optional(&self.pool)
        .await?;

        Ok(game)
    }
}
